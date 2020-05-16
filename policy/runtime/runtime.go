// Copyright 2020 Google LLC
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

package runtime

import (
	"fmt"
	"reflect"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter"
	"github.com/google/cel-policy-templates-go/policy/model"

	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

func NewTemplate(reg model.Registry,
	mdl *model.Template,
	evalOpts... cel.ProgramOption) (*Template, error) {
	t := &Template{
		reg:     reg,
		mdl:     mdl,
		actPool: newRuleActivationPool(),
	}
	if mdl.Validator != nil {
		val, err := t.newEvaluator(mdl.Validator, evalOpts...)
		if err != nil {
			return nil, err
		}
		t.validator = val
	}
	if mdl.Evaluator != nil {
		eval, err := t.newEvaluator(mdl.Evaluator, evalOpts...)
		if err != nil {
			return nil, err
		}
		t.evaluator = eval
	}
	return t, nil
}

type Template struct {
	reg       model.Registry
	mdl       *model.Template
	validator *evaluator
	evaluator *evaluator
	actPool   *ruleActivationPool
}

func (t *Template) Name() string {
	return t.mdl.Metadata.Name
}

func (t *Template) Validate(src *model.Source, inst *model.Instance) *cel.Issues {
	if t.validator == nil {
		return nil
	}
	errs := common.NewErrors(src)
	decs, err := t.evalInternal(t.validator, inst, interpreter.EmptyActivation())
	if err != nil {
		errs.ReportError(common.NoLocation, err.Error())
		return cel.NewIssues(errs)
	}
	if decs == nil || len(decs) == 0 {
		return nil
	}
	for _, d := range decs {
		loc, found := inst.Info.LocationByID(d.RuleID)
		if !found {
			loc = common.NoLocation
		}
		violation, err := d.Value.ConvertToNative(mapStrIface)
		violationMap := violation.(map[string]interface{})
		if err != nil {
			errs.ReportError(loc, err.Error())
		}
		det, found := violationMap["details"]
		if found {
			errs.ReportError(loc, "%s. details: %v", violationMap["message"], det)
		} else {
			errs.ReportError(loc, "%s", violationMap["message"])
		}

	}
	iss := cel.NewIssues(errs)
	return iss
}

func (t *Template) Eval(inst *model.Instance, vars interpreter.Activation) ([]*model.DecisionValue, error) {
	// TODO: support incremental evaluation, both for debug and for aggregation simplicity.
	if t.evaluator == nil {
		return nil, nil
	}
	return t.evalInternal(t.evaluator, inst, vars)
}

func (t *Template) evalInternal(eval *evaluator,
	inst *model.Instance,
	vars interpreter.Activation) ([]*model.DecisionValue, error) {
	ruleAct := t.actPool.Setup(vars)
	defer t.actPool.Put(ruleAct)
	var errs []error
	var decisions []*model.DecisionValue
	for _, r := range inst.Rules {
		ruleAct.rule = r
		decs, err := eval.eval(ruleAct)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, d := range decs {
			d.RuleID = r.GetID()
		}
		decisions = append(decisions, decs...)
	}
	if len(errs) != 0 {
		fmt.Println(errs)
	}
	return decisions, nil
}

func (t *Template) newEvaluator(mdl *model.Evaluator,
	evalOpts... cel.ProgramOption) (*evaluator, error) {
	terms := make(map[string]cel.Program, len(mdl.Terms))
	// Expose the cel EvalOptions as policy.EvalOption functions.
	evalOpts = append(evalOpts, cel.EvalOptions(cel.OptOptimize))
	env, err := t.newEnv(mdl.Environment)
	if err != nil {
		return nil, err
	}
	termDecls := make([]*exprpb.Decl, len(mdl.Terms))
	for i, t := range mdl.Terms {
		term, err := env.Program(t.Expr, evalOpts...)
		if err != nil {
			return nil, err
		}
		terms[t.Name] = term
		termDecls[i] = decls.NewIdent(t.Name, t.Expr.ResultType(), nil)
	}
	prodEnv, err := env.Extend(cel.Declarations(termDecls...))
	if err != nil {
		return nil, err
	}
	prods := make([]*prod, len(mdl.Productions))
	for i, p := range mdl.Productions {
		match, err := prodEnv.Program(p.Match, evalOpts...)
		if err != nil {
			return nil, err
		}
		decs := make([]*decision, len(p.Decisions))
		for i, d := range p.Decisions {
			dec, err := prodEnv.Program(d.Output, evalOpts...)
			if err != nil {
				return nil, err
			}
			decs[i] = &decision{
				name: d.Name,
				prg:  dec,
			}
		}
		prods[i] = &prod{
			match:     match,
			decisions: decs,
		}
	}
	eval := &evaluator{
		mdl:     mdl,
		env:     env,
		terms:   terms,
		prods:   prods,
		actPool: newEvalActivationPool(terms),
	}
	return eval, nil
}

func (t *Template) newEnv(name string) (*cel.Env, error) {
	env := stdEnv
	if name != "" {
		var found bool
		env, found = t.reg.FindEnv(name)
		if !found {
			return nil, fmt.Errorf("no such environment: %s", name)
		}
	}
	if t.mdl.RuleTypes == nil {
		return env, nil
	}
	return env.Extend(
		t.mdl.RuleTypes.EnvOptions(env.TypeProvider())...,
	)
}

type evaluator struct {
	mdl *model.Evaluator
	env *cel.Env
	// TODO: change this to an array and rewrite terms to be register functions
	terms   map[string]cel.Program
	prods   []*prod
	actPool *evalActivationPool
}

func (eval *evaluator) eval(vars interpreter.Activation) ([]*model.DecisionValue, error) {
	act := eval.actPool.Setup(vars)
	defer eval.actPool.Put(act)

	var errs []error
	var decisions []*model.DecisionValue
	// TODO: track which decisions have been finalized.
	for _, p := range eval.prods {
		matches, _, err := p.match.Eval(act)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if matches != types.True {
			continue
		}
		for _, d := range p.decisions {
			out, det, err := d.prg.Eval(act)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			dv := model.NewDecisionValue(d.name, out, det)
			decisions = append(decisions, dv)
		}
	}
	if len(errs) != 0 {
		fmt.Println(errs)
	}
	return decisions, nil
}

type prod struct {
	match     cel.Program
	decisions []*decision
}

type decision struct {
	name string
	prg  cel.Program
}

type ruleActivation struct {
	input interpreter.Activation
	rule  model.Rule
}

func (ctx *ruleActivation) ResolveName(name string) (interface{}, bool) {
	if name == "rule" {
		return ctx.rule, true
	}
	return ctx.input.ResolveName(name)
}

func (ctx *ruleActivation) Parent() interpreter.Activation {
	return ctx.input
}

func newRuleActivationPool() *ruleActivationPool {
	return &ruleActivationPool{
		Pool: sync.Pool{
			New: func() interface{} {
				return &ruleActivation{}
			},
		},
	}
}

type ruleActivationPool struct {
	sync.Pool
}

func (pool *ruleActivationPool) Setup(vars interpreter.Activation) *ruleActivation {
	act := pool.Get().(*ruleActivation)
	act.input = vars
	return act
}

type evaluatorActivation struct {
	input     interpreter.Activation
	terms     map[string]cel.Program
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
	cval, _, err := term.Eval(ctx)
	if err != nil {
		return types.NewErr("%s", err), true
	}
	ctx.memoTerms[name] = cval
	return cval, true
}

func (ctx *evaluatorActivation) Parent() interpreter.Activation {
	return nil
}

func newEvalActivationPool(terms map[string]cel.Program) *evalActivationPool {
	return &evalActivationPool{
		Pool: sync.Pool{
			New: func() interface{} {
				return &evaluatorActivation{
					terms:     terms,
					memoTerms: make(map[string]ref.Val, len(terms)),
				}
			},
		},
	}
}

type evalActivationPool struct {
	sync.Pool
}

func (pool *evalActivationPool) Setup(vars interpreter.Activation) *evaluatorActivation {
	act := pool.Get().(*evaluatorActivation)
	act.input = vars
	for k := range act.memoTerms {
		delete(act.memoTerms, k)
	}
	return act
}

var (
	stdEnv      *cel.Env
	mapStrIface reflect.Type
)

func init() {
	stdEnv, _ = cel.NewEnv()
	mapStrIface = reflect.TypeOf(map[string]interface{}{})
}
