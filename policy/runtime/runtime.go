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
	"errors"
	"fmt"
	"math"
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
func NewTemplate(res model.Resolver,
	mdl *model.Template,
	opts ...TemplateOption) (*Template, error) {
	t := &Template{
		res:          res,
		mdl:          mdl,
		decAggMap:    map[string]Aggregator{},
		exprOpts:     []cel.ProgramOption{},
		limits:       limits.NewLimits(),
		actPool:      newRuleActivationPool(),
		valSlotPool:  newDecisionSlotPool(1),
		evalSlotPool: newDecisionSlotPool(mdl.EvaluatorDecisionCount()),
	}
	var err error
	for _, opt := range opts {
		t, err = opt(t)
		if err != nil {
			return nil, err
		}
	}
	if mdl.Validator != nil {
		termCnt := len(mdl.Validator.Terms)
		if t.limits.ValidatorTermLimit >= 0 && termCnt > t.limits.ValidatorTermLimit {
			return nil, fmt.Errorf(
				"validator term limit set to %d, but %d found",
				t.limits.ValidatorTermLimit, termCnt)
		}
		prodCnt := len(mdl.Validator.Productions)
		if t.limits.ValidatorProductionLimit >= 0 && prodCnt > t.limits.ValidatorProductionLimit {
			return nil, fmt.Errorf(
				"validator production limit set to %d, but %d found",
				t.limits.ValidatorProductionLimit, prodCnt)
		}
		val, err := t.newEvaluator(mdl.Validator, -1, t.exprOpts...)
		if err != nil {
			return nil, err
		}
		t.validator = val
	}
	if mdl.Evaluator != nil {
		termCnt := len(mdl.Evaluator.Terms)
		if t.limits.EvaluatorTermLimit >= 0 && termCnt > t.limits.EvaluatorTermLimit {
			return nil, fmt.Errorf(
				"evaluator term limit set to %d, but %d found",
				t.limits.EvaluatorTermLimit, termCnt)
		}
		prodCnt := len(mdl.Evaluator.Productions)
		if t.limits.EvaluatorProductionLimit >= 0 && prodCnt > t.limits.EvaluatorProductionLimit {
			return nil, fmt.Errorf(
				"evaluator production limit set to %d, but %d found",
				t.limits.EvaluatorProductionLimit, prodCnt)
		}
		eval, err := t.newEvaluator(mdl.Evaluator, t.limits.EvaluatorExprCostLimit, t.exprOpts...)
		if err != nil {
			return nil, err
		}
		t.evaluator = eval
	}
	return t, nil
}

// Template represents an evaluable version of a model.Template.
type Template struct {
	res       model.Resolver
	mdl       *model.Template
	limits    *limits.Limits
	decAggMap map[string]Aggregator
	exprOpts  []cel.ProgramOption

	validator    *evaluator
	evaluator    *evaluator
	actPool      *ruleActivationPool
	valSlotPool  *decisionSlotPool
	evalSlotPool *decisionSlotPool
}

// Eval returns the evaluation result of a policy instance against a given set of variables.
func (t *Template) Eval(inst *model.Instance,
	vars interpreter.Activation,
	selector model.DecisionSelector) ([]model.DecisionValue, error) {
	slots := t.evalSlotPool.Setup()
	decs, err := t.evalInternal(t.evaluator, inst, vars, selector, slots)
	t.evalSlotPool.Put(slots)
	return decs, err
}

// FindAggregator returns the Aggregator for the decision if one is found.
func (t *Template) FindAggregator(name string) (Aggregator, bool) {
	agg, found := t.decAggMap[name]
	return agg, found
}

// Name returns the template's metadata name value.
func (t *Template) Name() string {
	return t.mdl.Metadata.Name
}

// Validate checks the content of an instance to ensure it conforms with the validation rules
// present within the template, if any.
func (t *Template) Validate(src *model.Source, inst *model.Instance) *cel.Issues {
	if t == nil || t.validator == nil {
		return nil
	}
	errs := common.NewErrors(src)
	slots := t.valSlotPool.Setup()
	defer t.valSlotPool.Put(slots)

	decs, err := t.evalInternal(t.validator, inst, noVars, nil, slots)
	if err != nil {
		errs.ReportError(common.NoLocation, err.Error())
		return cel.NewIssues(errs)
	}
	if decs == nil || len(decs) == 0 {
		return nil
	}
	if len(decs) > 1 {
		errs.ReportError(common.NoLocation,
			"multiple decisions reported, expected only one. values=%v",
			decs)
	}
	ruleMap := t.constructRulesMap(inst.Rules)
	for _, d := range decs {
		listDec := d.(*model.ListDecisionValue)
		vals := listDec.Values()
		rules := listDec.RuleIDs()
		for i, v := range vals {
			loc, found := inst.Meta.LocationByID(rules[i])
			if !found {
				loc = common.NoLocation
			}
			violation, err := v.ConvertToNative(mapStrIface)
			violationMap := violation.(map[string]interface{})
			if err != nil {
				errs.ReportError(loc, err.Error())
			}
			f, found := violationMap["field"]
			if found {
				field, ok := f.(string)
				if ok {
					rule := ruleMap[rules[i]]
					fieldID := rule.GetFieldID(field)
					fieldLoc, found := inst.Meta.LocationByID(fieldID)
					if found {
						loc = fieldLoc
					}
				}
			}
			det, found := violationMap["details"]
			if found {
				errs.ReportError(loc, "%s. details: %v", violationMap["message"], det)
			} else {
				errs.ReportError(loc, "%s", violationMap["message"])
			}
		}
	}
	iss := cel.NewIssues(errs)
	return iss
}

func (t *Template) constructRulesMap(rules []model.Rule) map[int64]model.Rule {
	ruleMap := make(map[int64]model.Rule, len(rules))
	for _, rule := range rules {
		ruleMap[rule.GetID()] = rule
	}
	return ruleMap
}

func (t *Template) evalInternal(eval *evaluator,
	inst *model.Instance,
	vars interpreter.Activation,
	selector model.DecisionSelector,
	slots *decisionSlots) ([]model.DecisionValue, error) {
	ruleAct := t.actPool.Setup(vars)
	ruleAct.tmplMetadata = t.mdl.MetadataMap()
	ruleAct.instMetadata = inst.MetadataMap()

	// Singleton policy without a schema.
	if t.mdl.RuleTypes == nil {
		err := eval.eval(nil, selector, ruleAct, slots)
		t.actPool.Put(ruleAct)
		if err != nil {
			return nil, err
		}
		return slotsToDecisions(slots), nil
	}
	// One or more rules present in the policy.
	if t.limits.RuleLimit >= 0 && len(inst.Rules) > t.limits.RuleLimit {
		return nil, fmt.Errorf(
			"rule limit set to %d, but %d found",
			t.limits.RuleLimit, len(inst.Rules))
	}
	for _, rule := range inst.Rules {
		err := eval.eval(rule, selector, ruleAct, slots)
		if err != nil {
			t.actPool.Put(ruleAct)
			return nil, err
		}
	}
	t.actPool.Put(ruleAct)
	return slotsToDecisions(slots), nil
}

func (t *Template) newEvaluator(mdl *model.Evaluator,
	exprCostLimit int,
	evalOpts ...cel.ProgramOption) (*evaluator, error) {
	terms := make(map[string]cel.Program, len(mdl.Terms))
	evalOpts = append(evalOpts, cel.EvalOptions(cel.OptOptimize))
	env, err := t.newEnv(mdl.Environment)
	if err != nil {
		return nil, err
	}
	rangeCnt := len(mdl.Ranges)
	if t.limits.RangeLimit >= 0 && rangeCnt > t.limits.RangeLimit {
		return nil, fmt.Errorf(
			"range limit set to %d, but %d found",
			t.limits.RangeLimit, rangeCnt)
	}
	var cost int64
	ranges := make([]iterable, rangeCnt)
	for i, r := range mdl.Ranges {
		rangeType := r.Expr.ResultType()
		rangePrg, err := env.Program(r.Expr)
		if err != nil {
			return nil, err
		}
		_, max := cel.EstimateCost(rangePrg)
		cost = addAndCap(cost, max)
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
		_, max := cel.EstimateCost(term)
		cost = addAndCap(cost, max)
	}

	prods := make([]*prod, len(mdl.Productions))
	decSlotMap := make(map[string]int)
	nextSlot := 0
	for i, p := range mdl.Productions {
		match, err := env.Program(p.Match, evalOpts...)
		if err != nil {
			return nil, err
		}
		_, max := cel.EstimateCost(match)
		cost = addAndCap(cost, max)
		decCnt := len(p.Decisions)
		if t.limits.EvaluatorDecisionLimit >= 0 && decCnt > t.limits.EvaluatorDecisionLimit {
			return nil, fmt.Errorf(
				"decision limit set to %d, but %d found",
				t.limits.EvaluatorDecisionLimit, decCnt)
		}
		decs := make([]*decision, decCnt)
		for i, d := range p.Decisions {
			dec, err := env.Program(d.Output, evalOpts...)
			if err != nil {
				return nil, err
			}
			_, max := cel.EstimateCost(dec)
			cost = addAndCap(cost, max)
			slot, found := decSlotMap[d.Name]
			if !found {
				slot = nextSlot
				decSlotMap[d.Name] = nextSlot
				nextSlot++
			}
			agg, found := t.FindAggregator(d.Name)
			if !found {
				agg = &CollectAggregator{name: d.Name}
			}
			decs[i] = &decision{
				name: d.Name,
				slot: slot,
				prg:  dec,
				agg:  agg,
			}
		}
		prods[i] = &prod{
			match:     match,
			decisions: decs,
		}
	}
	// Cost is greater than the limit.
	if exprCostLimit >= 0 && cost > int64(exprCostLimit) {
		return nil, fmt.Errorf("evaluator expression cost limit set to %d, but %d found", exprCostLimit, cost)
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

// addAndCap returns the max int64 if the cost overflows after the addition.
func addAndCap(cost, addend int64) int64 {
	result := cost + addend
	if result < 0 {
		return math.MaxInt64
	}
	return result
}

func (t *Template) newEnv(name string) (*cel.Env, error) {
	mdlEnv, mdlEnvFound := t.res.FindEnv(name)
	exprEnv, exprEnvFound := t.res.FindExprEnv(name)
	if !mdlEnvFound || !exprEnvFound {
		if name == "" {
			return nil, errors.New("missing default environment")
		}
		return nil, fmt.Errorf("no such environment: %s", name)
	}
	env, err := exprEnv.Extend(mdlEnv.ExprEnvOptions()...)
	if err != nil {
		return nil, err
	}
	if t.mdl.RuleTypes == nil {
		return env, nil
	}
	opts, err := t.mdl.RuleTypes.EnvOptions(env.TypeProvider())
	if err != nil {
		return nil, err
	}
	return env.Extend(opts...)
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

func (eval *evaluator) eval(rule model.Rule,
	selector model.DecisionSelector,
	vars *ruleActivation,
	slots *decisionSlots) error {
	vars.rule = rule
	// Fast-path evaluation without ranges.
	if len(eval.ranges) == 0 {
		act := eval.actPool.Setup(vars)
		err := eval.evalProductions(rule, selector, act, slots)
		eval.actPool.Put(act)
		return err
	}
	// Range-based evaluation.
	var errs []error
	rangeIt := eval.rangeIterator(vars)
	err := rangeIt.init(vars)
	if err != nil {
		return err
	}
	for rangeIt.hasNext() {
		rangeIt.next(vars)
		act := eval.actPool.Setup(vars)
		err := eval.evalProductions(rule, selector, act, slots)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		eval.actPool.Put(act)
	}
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

func (eval *evaluator) evalProductions(rule model.Rule,
	selector model.DecisionSelector,
	act interpreter.Activation,
	slots *decisionSlots) error {
	var errs []error
	for _, p := range eval.prods {
		// TODO: update this to support finalization on a per-rule basis
		// as this will support fine-tuning of the aggregation as a per-rule,
		// per-policy, or per-policy set.
		if !p.hasMoreDecisions(slots, selector) {
			continue
		}
		matches, _, err := p.match.Eval(act)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if matches != types.True {
			continue
		}
		for _, d := range p.decisions {
			if selector != nil && !selector(d.name) {
				continue
			}
			// initialize the slot
			dv := slots.values[d.slot]
			if dv == nil {
				dv = d.agg.DefaultDecision()
			}
			dv, err = d.agg.Aggregate(d.prg, act, dv, rule)
			if err != nil {
				errs = append(errs, err)
			} else {
				slots.values[d.slot] = dv
			}
		}
	}
	if len(errs) != 0 {
		// TODO: report a better multi-error
		return errs[0]
	}
	return nil
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
	// TODO: support references. When references are present, they need to be accumulated
	// separately from the decisions since the referenced name may be derived from the instance.
}

func (p *prod) hasMoreDecisions(slots *decisionSlots,
	selector model.DecisionSelector) bool {
	for _, d := range p.decisions {
		if d == nil {
			continue
		}
		if selector != nil && !selector(d.name) {
			continue
		}
		if !d.isFinal(slots) {
			return true
		}
	}
	return false
}

type decision struct {
	name string
	slot int
	prg  cel.Program
	agg  Aggregator
}

func (d *decision) isFinal(slots *decisionSlots) bool {
	dv := slots.values[d.slot]
	return dv != nil && dv.IsFinal()
}

type decisionSlots struct {
	values []model.DecisionValue
}

func slotsToDecisions(slots *decisionSlots) []model.DecisionValue {
	var decisions []model.DecisionValue
	for _, dv := range slots.values {
		if dv != nil {
			decisions = append(decisions, dv)
		}
	}
	return decisions
}

func newDecisionSlotPool(size int) *decisionSlotPool {
	return &decisionSlotPool{
		Pool: &sync.Pool{
			New: func() interface{} {
				return &decisionSlots{
					values: make([]model.DecisionValue, size),
				}
			},
		},
	}
}

type decisionSlotPool struct {
	*sync.Pool
}

func (pool *decisionSlotPool) Setup() *decisionSlots {
	slots := pool.Get().(*decisionSlots)
	for i := range slots.values {
		slots.values[i] = nil
	}
	return slots
}

type ruleActivation struct {
	input        interpreter.Activation
	rangeVars    map[string]ref.Val
	rule         model.Rule
	tmplMetadata map[string]interface{}
	instMetadata map[string]interface{}
}

func (ctx *ruleActivation) ResolveName(name string) (interface{}, bool) {
	if name == "rule" {
		return ctx.rule, true
	}
	if name == "template" {
		return ctx.tmplMetadata, true
	}
	if name == "instance" {
		return ctx.instMetadata, true
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
	mapStrIface = reflect.TypeOf(map[string]interface{}{})
	noVars      = interpreter.EmptyActivation()
)
