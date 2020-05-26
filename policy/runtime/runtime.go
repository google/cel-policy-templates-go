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

// Package runtime implements the evaluation model for templates / instances.
package runtime

import (
	"fmt"
	"reflect"
	"sync"

	"github.com/google/cel-policy-templates-go/policy/limits"
	"github.com/google/cel-policy-templates-go/policy/model"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/google/cel-go/interpreter"

	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

// NewTemplate creates a validator / evaluator pair for a model.Template.
func NewTemplate(reg model.Registry,
	mdl *model.Template,
	limits *limits.Limits,
	evalOpts ...cel.ProgramOption) (*Template, error) {
	t := &Template{
		reg:     reg,
		mdl:     mdl,
		limits:  limits,
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

// Template represents an evaluable version of a model.Template.
type Template struct {
	reg       model.Registry
	mdl       *model.Template
	limits    *limits.Limits
	validator *evaluator
	evaluator *evaluator
	actPool   *ruleActivationPool
}

// Name returns the template's metadata name value.
func (t *Template) Name() string {
	return t.mdl.Metadata.Name
}

// Validate checks the content of an instance to ensure it conforms with the validation rules
// present within the template, if any.
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

// Eval returns the evaluation result of a policy instance against a given set of variables.
func (t *Template) Eval(inst *model.Instance,
	vars interpreter.Activation) ([]*model.DecisionValue, error) {
	// TODO: support incremental evaluation, both for debug and for aggregation simplicity.
	return t.evalInternal(t.evaluator, inst, vars)
}

func (t *Template) evalInternal(eval *evaluator,
	inst *model.Instance,
	vars interpreter.Activation) ([]*model.DecisionValue, error) {
	ruleAct := t.actPool.Setup(vars)
	defer t.actPool.Put(ruleAct)
	var errs []error
	var decisions []*model.DecisionValue
	// Singleton policy without a schema.
	if t.mdl.RuleTypes == nil {
		return eval.eval(ruleAct)
	}
	// One or more rules present in the policy.
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
		// TODO: report a richer error
		return nil, errs[0]
	}
	return decisions, nil
}

func (t *Template) newEvaluator(mdl *model.Evaluator,
	evalOpts ...cel.ProgramOption) (*evaluator, error) {
	terms := make(map[string]cel.Program, len(mdl.Terms))
	// TODO: Expose the cel EvalOptions as policy.EvalOption functions.
	evalOpts = append(evalOpts, cel.EvalOptions(cel.OptOptimize))
	env, err := t.newEnv(mdl.Environment)
	if err != nil {
		return nil, err
	}
	rangeCnt := len(mdl.Ranges)
	if rangeCnt > t.limits.RangeLimit {
		return nil, fmt.Errorf(
			"range limit set to %d, but %d found",
			t.limits.RangeLimit, rangeCnt)
	}
	ranges := make([]iterable, rangeCnt)
	for i, r := range mdl.Ranges {
		rangeType := r.Expr.ResultType()
		rangePrg, err := env.Program(r.Expr)
		if err != nil {
			return nil, err
		}
		switch rangeType.TypeKind.(type) {
		case *exprpb.Type_MapType_:
			mr := &mapRange{
				key: r.Key,
				val: r.Value,
				prg: rangePrg,
			}
			ranges[i] = mr
		case *exprpb.Type_ListType_:
			lr := &listRange{
				idx: r.Key,
				val: r.Value,
				prg: rangePrg,
			}
			ranges[i] = lr
		}
	}
	for _, t := range mdl.Terms {
		term, err := env.Program(t.Expr, evalOpts...)
		if err != nil {
			return nil, err
		}
		terms[t.Name] = term
	}

	prods := make([]*prod, len(mdl.Productions))
	for i, p := range mdl.Productions {
		match, err := env.Program(p.Match, evalOpts...)
		if err != nil {
			return nil, err
		}
		decs := make([]*decision, len(p.Decisions))
		for i, d := range p.Decisions {
			dec, err := env.Program(d.Output, evalOpts...)
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
		ranges:  ranges,
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
	mdl    *model.Evaluator
	env    *cel.Env
	ranges []iterable
	// TODO: change this to an array and rewrite terms to be register functions
	terms   map[string]cel.Program
	prods   []*prod
	actPool *evalActivationPool
}

func (eval *evaluator) eval(vars *ruleActivation) ([]*model.DecisionValue, error) {
	// Fast-path evaluation without ranges.
	if len(eval.ranges) == 0 {
		act := eval.actPool.Setup(vars)
		defer eval.actPool.Put(act)
		return eval.evalProductions(act)
	}
	// Range-based evaluation.
	var errs []error
	var decisions []*model.DecisionValue
	rangeIt := eval.rangeIterator(vars)
	err := rangeIt.init(vars)
	if err != nil {
		return nil, err
	}
	for rangeIt.hasNext() {
		rangeIt.next(vars)
		act := eval.actPool.Setup(vars)
		dv, err := eval.evalProductions(act)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		decisions = append(decisions, dv...)
		eval.actPool.Put(act)
	}
	return decisions, nil
}

func (eval *evaluator) evalProductions(act interpreter.Activation) ([]*model.DecisionValue, error) {
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
		// TODO: report a better multi-error
		return nil, errs[0]
	}
	return decisions, nil
}

func (eval *evaluator) rangeIterator(vars *ruleActivation) *rangeEvalIterator {
	var iters []rangeIterator
	for _, r := range eval.ranges {
		iters = append(iters, r.iter(vars))
	}
	return &rangeEvalIterator{
		iters: iters,
		count: len(iters),
	}
}

type rangeEvalIterator struct {
	hasFirst  bool
	firstIter bool
	iters     []rangeIterator
	count     int
}

func (it *rangeEvalIterator) init(vars *ruleActivation) error {
	// Ensure ranges are initialized with values appropriately.
	for _, i := range it.iters {
		err := i.reset(vars)
		if err != nil {
			return err
		}
		if i.hasNext() {
			err = i.next(vars)
			if err != nil {
				return err
			}
			it.firstIter = true
			it.hasFirst = true
		}
	}
	return nil
}

func (it *rangeEvalIterator) hasNext() bool {
	// After the first iteration, the hasNext() works as expected, but on the first pass the
	// initialization value represents the first iteration step.
	if it.firstIter {
		return it.hasFirst
	}
	for _, i := range it.iters {
		if i.hasNext() {
			return true
		}
	}
	return false
}

func (it *rangeEvalIterator) next(vars *ruleActivation) error {
	// There's a bit of an initialization challenge here where the ranges need to be initialized
	// in order to have _a_ value and for dependent ranges to be evaluated properly. After the
	// first iteration, the ranges and iterators are properly initialized and properly reset
	// when the inner ranges are reach the end of iteration.
	if it.firstIter {
		it.firstIter = false
		return nil
	}
	last := it.iters[it.count-1]
	if last.hasNext() {
		return last.next(vars)
	}
	for i := it.count - 2; i >= 0; i-- {
		prev := it.iters[i]
		if prev.hasNext() {
			prev.next(vars)
			for j := it.count - 1; j > i; j-- {
				next := it.iters[j]
				next.reset(vars)
				if next.hasNext() {
					next.next(vars)
				}
			}
		}
	}
	return nil
}

func (it *rangeEvalIterator) reset(*ruleActivation) error {
	// do nothing.
	return nil
}

type iterable interface {
	iter(*ruleActivation) rangeIterator
}

type rangeIterator interface {
	hasNext() bool
	next(*ruleActivation) error
	reset(*ruleActivation) error
}

type mapRange struct {
	key *exprpb.Decl
	val *exprpb.Decl
	prg cel.Program
}

func (mr *mapRange) iter(vars *ruleActivation) rangeIterator {
	return &mapIterator{
		mapRange: mr,
	}
}

type mapIterator struct {
	*mapRange
	mapVal traits.Mapper
	mapIt  traits.Iterator
}

func (it *mapIterator) hasNext() bool {
	return it.mapIt.HasNext() == types.True
}

func (it *mapIterator) next(vars *ruleActivation) error {
	key := it.mapIt.Next()
	if it.mapRange.key != nil {
		vars.rangeVars[it.mapRange.key.GetName()] = key
	}
	if it.mapRange.val != nil {
		vars.rangeVars[it.mapRange.val.GetName()] = it.mapVal.Get(key)
	}
	return nil
}

func (it *mapIterator) reset(vars *ruleActivation) error {
	val, _, err := it.mapRange.prg.Eval(vars)
	if err != nil {
		return err
	}
	mapVal, ok := val.(traits.Mapper)
	if !ok {
		return fmt.Errorf("iterator reset failed: got %T, wanted map", val)
	}
	it.mapVal = mapVal
	it.mapIt = mapVal.Iterator().(traits.Iterator)
	return nil
}

type listRange struct {
	idx *exprpb.Decl
	val *exprpb.Decl
	prg cel.Program
}

func (lr *listRange) iter(vars *ruleActivation) rangeIterator {
	return &listIterator{
		listRange: lr,
	}
}

type listIterator struct {
	*listRange
	listVal traits.Indexer
	idx     types.Int
	sz      types.Int
}

func (it *listIterator) hasNext() bool {
	return it.idx < it.sz
}

func (it *listIterator) next(vars *ruleActivation) error {
	if it.listRange.idx != nil {
		vars.rangeVars[it.listRange.idx.GetName()] = it.idx
	}
	if it.listRange.val != nil {
		vars.rangeVars[it.listRange.val.GetName()] = it.listVal.Get(it.idx)
	}
	it.idx++
	return nil
}

func (it *listIterator) reset(vars *ruleActivation) error {
	// Errors are packaged up into the 'val' element.
	val, _, err := it.listRange.prg.Eval(vars)
	if err != nil {
		return err
	}
	listVal, ok := val.(traits.Lister)
	if !ok {
		return fmt.Errorf("reset iterator failed: got %T, wanted list", val)
	}
	it.listVal = listVal
	it.idx = types.Int(0)
	it.sz = listVal.Size().(types.Int)
	return nil
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
	input     interpreter.Activation
	rangeVars map[string]ref.Val
	rule      model.Rule
}

func (ctx *ruleActivation) ResolveName(name string) (interface{}, bool) {
	if name == "rule" {
		return ctx.rule, true
	}
	if ctx.rangeVars != nil {
		val, found := ctx.rangeVars[name]
		if found {
			return val, true
		}
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
				return &ruleActivation{
					rangeVars: map[string]ref.Val{},
				}
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
