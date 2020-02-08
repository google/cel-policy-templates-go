// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package policy

import (
	"log"
	"strings"
	"sync"

	"github.com/golang/protobuf/proto"
	"gopkg.in/yaml.v3"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter"

	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

type evaluatorModel struct {
	template string
	src      *file
	termSrcs map[string]*termSrc
	ruleSrcs []*ruleSrc
	errors   *common.Errors
	issues   *cel.Issues
}

func unmarshalEvaluatorModel(f *file) (*evaluatorModel, error) {
	eval := &evalCrd{}
	err := f.unmarshalYaml(eval)
	if err != nil {
		return nil, err
	}
	terms := make(map[string]*termSrc, len(eval.Spec.Terms))
	for name, expr := range eval.Spec.Terms {
		termExpr := f.newLocalExpr(expr.Value, expr.Line, expr.Column-1)
		terms[name] = &termSrc{
			name: name,
			expr: termExpr,
		}
	}
	i := 0
	rules := make([]*ruleSrc, len(eval.Spec.Rules), len(eval.Spec.Rules))
	for _, rule := range eval.Spec.Rules {
		matchExpr := f.newLocalExpr(rule.Match.Value, rule.Match.Line, rule.Match.Column-1)
		outExpr := f.newLocalExpr(rule.Output.Value, rule.Output.Line, rule.Output.Column-1)
		rules[i] = &ruleSrc{
			match:  matchExpr,
			output: outExpr,
		}
		i++
	}
	errs := common.NewErrors(f)
	iss := cel.NewIssues(errs)
	return &evaluatorModel{
		src:      f,
		template: eval.Spec.Template,
		termSrcs: terms,
		ruleSrcs: rules,
		errors:   errs,
		issues:   iss,
	}, nil
}

func (e *evaluatorModel) bind(env *cel.Env, opts ...cel.ProgramOption) (*evaluator, error) {
	// Compute the dependencies between terms and compile them.
	err := e.computeDeps(env)
	if err != nil {
		return nil, err
	}
	terms, err := e.compileTerms(env, opts)
	if err != nil {
		return nil, err
	}
	// Build the rules environment.
	i := 0
	termDecls := make([]*exprpb.Decl, len(terms), len(terms))
	for name, term := range terms {
		termDecls[i] = decls.NewIdent(name, term.termType(), nil)
		i++
	}
	ruleEnv, err := env.Extend(cel.Declarations(termDecls...))
	if err != nil {
		return nil, err
	}
	// Compile the rules.
	rules, err := e.compileRules(ruleEnv, opts)
	if err != nil {
		return nil, err
	}
	evalTerms := make(map[string]*evalNode, len(terms))
	for name, term := range terms {
		evalTerms[name] = term.eval
	}
	// Produce a new evaluator.
	return &evaluator{
		template:   e.template,
		rules:      rules,
		activation: &evaluatorActivation{terms: evalTerms},
	}, nil
}

func (e *evaluatorModel) templateName() string {
	return e.template
}

func (e *evaluatorModel) computeDeps(env *cel.Env) error {
	// Check for cycles within the term definitions.
	i := 0
	termDecls := make([]*exprpb.Decl, len(e.termSrcs), len(e.termSrcs))
	for name := range e.termSrcs {
		termDecls[i] = decls.NewIdent(name, decls.Dyn, nil)
		i++
	}
	globalEnv, err := env.Extend(cel.Declarations(termDecls...))
	if err != nil {
		return err
	}
	for _, ts := range e.termSrcs {
		ts.depSet = findDeps(ts.expr, globalEnv)
	}

	// Compute whether the are any cycles in the dependency lists.
	visited := make(map[string]struct{})
	for name, ts := range e.termSrcs {
		recStack := []string{}
		if e.isCyclic(ts, visited, &recStack) {
			e.errors.ReportError(ts.expr.Location(),
				"cycle detected: %s -> %s",
				strings.Join(recStack, " -> "), name)
			break
		}
	}
	return e.issues.Err()
}

func (e *evaluatorModel) isCyclic(ts *termSrc,
	visited map[string]struct{},
	stack *[]string) bool {
	for _, nm := range *stack {
		if nm == ts.name {
			return true
		}
	}
	if _, found := visited[ts.name]; found {
		return false
	}
	*stack = append(*stack, ts.name)
	visited[ts.name] = struct{}{}
	for v := range ts.depSet.variables {
		depTerm, isTerm := e.termSrcs[v]
		if isTerm && e.isCyclic(depTerm, visited, stack) {
			return true
		}
	}
	*stack = (*stack)[:len(*stack)-1]
	return false
}

func (e *evaluatorModel) compileTerms(env *cel.Env,
	opts []cel.ProgramOption) (map[string]*evalTerm, error) {
	terms := map[string]*evalTerm{}
	for _, ts := range e.termSrcs {
		term, err := e.compileTerm(ts, env, opts, terms)
		if err != nil {
			return nil, err
		}
		terms[ts.name] = term
	}
	return terms, e.issues.Err()
}

func (e *evaluatorModel) compileTerm(ts *termSrc, env *cel.Env,
	opts []cel.ProgramOption, terms map[string]*evalTerm) (*evalTerm, error) {
	if t, found := terms[ts.name]; found {
		return t, nil
	}
	termDecls := []*exprpb.Decl{}
	for name := range ts.depSet.variables {
		depSrc, found := e.termSrcs[name]
		if !found {
			continue
		}
		depTerm, err := e.compileTerm(depSrc, env, opts, terms)
		if err != nil {
			return nil, err
		}
		terms[name] = depTerm
		termType := decls.Error
		if depTerm != nil {
			termType = depTerm.termType()
		}
		termDecls = append(termDecls, decls.NewIdent(name, termType, nil))
	}

	termEnv, err := env.Extend(cel.Declarations(termDecls...))
	if err != nil {
		return nil, err
	}
	ast, iss := compile(ts.expr, termEnv)
	if iss != nil {
		e.issues.Append(iss)
		return nil, nil
	}
	prg, err := termEnv.Program(ast,
		append(opts, cel.EvalOptions(cel.OptOptimize))...)
	if err != nil {
		return nil, err
	}
	return &evalTerm{
		name:   ts.name,
		depSet: ts.depSet,
		eval: &evalNode{
			expr:    ts.expr,
			env:     termEnv,
			ast:     ast,
			program: prg,
		},
	}, nil
}

func (e *evaluatorModel) compileRules(env *cel.Env,
	opts []cel.ProgramOption) ([]*evalRule, error) {
	i := 0
	rules := make([]*evalRule, len(e.ruleSrcs), len(e.ruleSrcs))
	for _, rule := range e.ruleSrcs {
		matchAst, iss := compile(rule.match, env)
		if iss != nil {
			e.issues.Append(iss)
		}
		if iss == nil && !proto.Equal(matchAst.ResultType(), decls.Bool) {
			e.errors.ReportError(
				rule.match.Location(),
				"matcher must be a boolean expression")
		}
		if e.issues.Err() != nil {
			return nil, e.issues.Err()
		}
		matchPrg, err := env.Program(matchAst, append(opts, cel.EvalOptions(cel.OptOptimize))...)
		if err != nil {
			return nil, err
		}
		outAst, iss := compile(rule.output, env)
		if iss != nil {
			e.issues.Append(iss)
		}
		if e.issues.Err() != nil {
			return nil, e.issues.Err()
		}
		outPrg, err := env.Program(outAst, append(opts, cel.EvalOptions(cel.OptOptimize))...)
		if err != nil {
			return nil, err
		}
		rules[i] = &evalRule{
			match: &evalNode{
				expr:    rule.match,
				env:     env,
				ast:     matchAst,
				program: matchPrg,
			},
			output: &evalNode{
				expr:    rule.output,
				env:     env,
				ast:     outAst,
				program: outPrg,
			},
		}
		i++
	}
	return rules, e.issues.Err()
}

type evaluator struct {
	template   string
	activation *evaluatorActivation
	rules      []*evalRule
}

func (eval *evaluator) Eval(vars interface{}) ([]ref.Val, error) {
	activation, err := evalActivationPool.Setup(vars, eval.activation.terms)
	if err != nil {
		return nil, err
	}
	decisions := []ref.Val{}
	errors := []error{}
	for _, rule := range eval.rules {
		matches, _, err := rule.match.program.Eval(activation)
		if err != nil {
			errors = append(errors, err)
			continue
		}
		if matches != types.True {
			continue
		}
		output, _, err := rule.output.program.Eval(activation)
		if err != nil {
			errors = append(errors, err)
			continue
		}
		decisions = append(decisions, output)
	}
	evalActivationPool.Put(activation)
	// TODO: this needs a real error handling strategy. There will be cases where errors will occur
	// and even though some portion of the evaluation may be completed, the error should be
	// observable to the caller.
	// If there is at least one decision, then return it.
	if len(decisions) != 0 {
		if len(errors) != 0 {
			log.Printf("decisions found, but errors encountered: %v\n", errors)
		}
		return decisions, nil
	}
	// Otherwise if there are errors, return the errors since the errors are implicitly ORed with
	// the decisions.
	if len(errors) != 0 {
		if len(errors) != 0 {
			log.Printf("evaluation encountered errors: %v\n", errors)
		}
		return nil, errors[0]
	}
	return decisions, nil
}

type evaluatorActivation struct {
	input     interpreter.Activation
	terms     map[string]*evalNode
	memoTerms map[string]ref.Val
}

// ResolveName implements the interpreter.Activation interface for CEL.
//
// The interface contract is such that CEL requests variables by name, and if present the raw value
// should be returned to the CEL runtime. If conversion to a CEL ref.Val is necessary to comlpete
// the evaluation, this is done just in time rather than eagerly.
//
// This activation also spawns additional CEL evaluations based on whether the variable name being
// requested refers to a 'term' in the CEL Policy Template. For the duration of the evaluation the
// term value is only computed once and then subsequently memoized.
func (ctx *evaluatorActivation) ResolveName(name string) (interface{}, bool) {
	val, found := ctx.input.ResolveName(name)
	if found {
		return val, true
	}
	val, found = ctx.memoTerms[name]
	if found {
		return val, true
	}
	term, found := ctx.terms[name]
	if !found {
		return nil, false
	}
	cval, _, err := term.program.Eval(ctx)
	if err != nil {
		return types.NewErr("%s", err), true
	}
	ctx.memoTerms[name] = cval
	return cval, true
}

func (ctx *evaluatorActivation) Parent() interpreter.Activation {
	return nil
}

type termSrc struct {
	name   string
	expr   *localExpr
	depSet *deps
}

type ruleSrc struct {
	match  *localExpr
	output *localExpr
}

type evalTerm struct {
	name   string
	depSet *deps
	eval   *evalNode
}

func (t *evalTerm) termType() *exprpb.Type {
	return t.eval.nodeType()
}

type evalRule struct {
	match  *evalNode
	output *evalNode
}

type evalNode struct {
	expr    *localExpr
	env     *cel.Env
	ast     *cel.Ast
	program cel.Program
}

func (n *evalNode) nodeType() *exprpb.Type {
	if n.ast == nil {
		return nil
	}
	return n.ast.ResultType()
}

type deps struct {
	variables map[string][]int64
}

func newDeps() *deps {
	return &deps{
		variables: make(map[string][]int64),
	}
}

func findDeps(src common.Source, env *cel.Env) *deps {
	ast, iss := compile(src, env)
	if iss != nil {
		return newDeps()
	}
	ce, _ := cel.AstToCheckedExpr(ast)
	depSet := newDeps()
	refMap := ce.GetReferenceMap()
	for id, ref := range refMap {
		if ref.GetName() != "" && ref.GetValue() == nil {
			// Variable
			varRef, found := depSet.variables[ref.GetName()]
			if !found {
				depSet.variables[ref.GetName()] = []int64{id}
			} else {
				depSet.variables[ref.GetName()] = append(varRef, id)
			}
		}
	}
	return depSet
}

func compile(src common.Source, env *cel.Env) (*cel.Ast, *cel.Issues) {
	parsed, iss := env.ParseSource(src)
	if iss != nil {
		return nil, iss
	}
	checked, iss := env.Check(parsed)
	if iss != nil {
		return nil, iss
	}
	return checked, nil
}

type evalCrd struct {
	APIVersion string            `yaml:"apiVersion"`
	Kind       string            `yaml:"kind"`
	Metadata   map[string]string `yaml:"metadata"`
	Spec       *evalSpecYaml     `yaml:"spec"`
}

type evalSpecYaml struct {
	Description string               `yaml:"description"`
	Environment string               `yaml:"environment"`
	Template    string               `yaml:"template"`
	Terms       map[string]yaml.Node `yaml:"terms"`
	Rules       []*evalRuleYaml      `yaml:"rules"`
}

type evalRuleYaml struct {
	Match  yaml.Node `yaml:"match"`
	Output yaml.Node `yaml:"output"`
}

type evaluatorActivationPool struct {
	sync.Pool
}

func (pool *evaluatorActivationPool) Setup(vars interface{},
	terms map[string]*evalNode) (*evaluatorActivation, error) {
	varActivation, err := interpreter.NewActivation(vars)
	if err != nil {
		return nil, err
	}
	activation := pool.Pool.Get().(*evaluatorActivation)
	activation.input = varActivation
	activation.terms = terms
	for k := range activation.memoTerms {
		delete(activation.memoTerms, k)
	}
	return activation, nil
}

var evalActivationPool = &evaluatorActivationPool{
	Pool: sync.Pool{
		New: func() interface{} {
			return &evaluatorActivation{
				memoTerms: make(map[string]ref.Val),
			}
		},
	},
}
