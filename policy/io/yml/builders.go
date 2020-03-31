// Copyright 2020 Google LLC
//
// Liceed under the Apache License, Version 2.0 (the "License");
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

package yml

import (
	"fmt"

	"github.com/google/cel-policy-templates-go/policy/config"
)

// objRef defines a series of methods used to build an object model from the YAML decode step.
type objRef interface {
	// id assigns the relative source element identifier to the object.
	id(id int64)

	// assign a primitive value to the object.
	//
	// If the object is not a primitive value, return an error.
	assign(value interface{}) error

	// prop creates an objRef for the property with the given name for building nested objects.
	//
	// If the object does not have the property or is not a map-like type, the method will return
	// an error.
	prop(id int64, name string) (objRef, error)

	// propAt creates an objRef for the item at the given 'idx' ordinal for building list entries.
	//
	// If the object is not a list or the index is not between 0 and the length of the list, the
	// function will return an error.
	propAt(idx interface{}) (objRef, error)
}

// newBaseBuilder returns a base builder which implements the core methods of the objRef interface.
func newBaseBuilder(typeName string) *baseBuilder {
	return &baseBuilder{typeName: typeName}
}

type baseBuilder struct {
	typeName string
}

// id is an implementation of the objRef interface method.
func (b *baseBuilder) id(id int64) {}

// assign is an implementation of the objRef interface method.
func (b *baseBuilder) assign(val interface{}) error {
	return valueNotAssignableToType(b.typeName, val)
}

// prop is an implementation of the objRef interface method.
func (b *baseBuilder) prop(id int64, name string) (objRef, error) {
	return nil, typeNotAssignableToType(b.typeName, "struct")
}

// propAt is an implementation of the objRef interface method.
func (b *baseBuilder) propAt(idx interface{}) (objRef, error) {
	return nil, typeNotAssignableToType(b.typeName, "list")
}

// newTemplateBuilder returns a builder for a config.Template instance.
func newTemplateBuilder(tmpl *config.Template) *templateBuilder {
	return &templateBuilder{
		baseBuilder: newBaseBuilder("template"),
		template:    tmpl,
	}
}

type templateBuilder struct {
	*baseBuilder
	template *config.Template
}

// id is an implementation of the objRef interface method.
func (b *templateBuilder) id(id int64) {
	b.template.ID = id
}

func (b *templateBuilder) prop(id int64, name string) (objRef, error) {
	field := config.NewStructField(id, name)
	builder := newDynValueBuilder(field.Ref)
	switch name {
	case "apiVersion":
		b.template.APIVersion = field
		return builder, nil
	case "description":
		b.template.Description = field
		return builder, nil
	case "kind":
		b.template.Kind = field
		return builder, nil
	case "metadata":
		sv := config.NewStructValue()
		field.Ref.Value = sv
		builder.sb = newStructBuilder(sv)
		b.template.Metadata = field
		return builder, nil
	case "schema":
		sv := config.NewStructValue()
		field.Ref.Value = sv
		builder.sb = newStructBuilder(sv)
		b.template.RuleSchema = field
		return builder, nil
	case "validator":
		validator := &config.Validator{ID: id}
		b.template.Validator = validator
		return newValidatorBuilder(validator), nil
	case "evaluator":
		evaluator := &config.Evaluator{ID: id}
		b.template.Evaluator = evaluator
		return newEvaluatorBuilder(evaluator), nil
	}
	return nil, noSuchProperty("template", name)
}

// newValidatorBuilder returns a builder for a config.Validator instance.
func newValidatorBuilder(val *config.Validator) *validatorBuilder {
	return &validatorBuilder{
		baseBuilder: newBaseBuilder("validator"),
		validator:   val,
	}
}

type validatorBuilder struct {
	*baseBuilder
	validator *config.Validator
}

func (b *validatorBuilder) prop(id int64, name string) (objRef, error) {
	field := config.NewStructField(id, name)
	builder := newDynValueBuilder(field.Ref)
	switch name {
	case "environment":
		b.validator.Environment = field
		return builder, nil
	case "terms":
		sv := config.NewStructValue()
		field.Ref.Value = sv
		builder.sb = newStructBuilder(sv)
		b.validator.Terms = field
		return builder, nil
	case "productions":
		p := &config.ValidatorProductions{
			ID:     id,
			Values: []*config.ValidatorProduction{},
		}
		b.validator.Productions = p
		return newValidatorProductionsBuilder(p), nil
	}
	return nil, noSuchProperty("validator", name)
}

// newValidationProductionsBuilder returns a builder for the validator production rules list.
func newValidatorProductionsBuilder(p *config.ValidatorProductions) *validatorProductionsBuilder {
	return &validatorProductionsBuilder{
		baseBuilder: newBaseBuilder("productions"),
		productions: p,
	}
}

type validatorProductionsBuilder struct {
	*baseBuilder
	productions *config.ValidatorProductions
}

func (b *validatorProductionsBuilder) propAt(idx interface{}) (objRef, error) {
	err := checkIndexRange(idx, len(b.productions.Values))
	if err != nil {
		return nil, err
	}
	p := &config.ValidatorProduction{}
	b.productions.Values = append(b.productions.Values, p)
	return newValidatorProductionBuilder(p), nil
}

// newValidationProductionBuilder returns a builder for a single config.ValidatorProduction.
func newValidatorProductionBuilder(p *config.ValidatorProduction) *validatorProductionBuilder {
	return &validatorProductionBuilder{
		baseBuilder: newBaseBuilder("production"),
		production:  p,
	}
}

type validatorProductionBuilder struct {
	*baseBuilder
	production *config.ValidatorProduction
}

func (b *validatorProductionBuilder) prop(id int64, name string) (objRef, error) {
	field := config.NewStructField(id, name)
	builder := newDynValueBuilder(field.Ref)
	switch name {
	case "match":
		b.production.Match = field
		return builder, nil
	case "message":
		b.production.Message = field
		return builder, nil
	case "details":
		b.production.Details = field
		return builder, nil
	}
	return nil, noSuchProperty("production", name)
}

// newEvaluatorBuilder returns a builder for a config.Evaluator.
func newEvaluatorBuilder(eval *config.Evaluator) *evaluatorBuilder {
	return &evaluatorBuilder{
		baseBuilder: newBaseBuilder("evaluator"),
		evaluator:   eval,
	}
}

type evaluatorBuilder struct {
	*baseBuilder
	evaluator *config.Evaluator
}

func (b *evaluatorBuilder) prop(id int64, name string) (objRef, error) {
	field := config.NewStructField(id, name)
	builder := newDynValueBuilder(field.Ref)
	switch name {
	case "environment":
		b.evaluator.Environment = field
		return builder, nil
	case "terms":
		sv := config.NewStructValue()
		field.Ref.Value = sv
		builder.sb = newStructBuilder(sv)
		b.evaluator.Terms = field
		return builder, nil
	case "productions":
		p := &config.EvaluatorProductions{
			ID:     id,
			Values: []*config.EvaluatorProduction{},
		}
		b.evaluator.Productions = p
		return newEvaluatorProductionsBuilder(p), nil
	}
	return nil, noSuchProperty("evaluator", name)
}

// newEvaluatorProductionsBuilder returns a builder for an evaluator productions list.
func newEvaluatorProductionsBuilder(p *config.EvaluatorProductions) *evaluatorProductionsBuilder {
	return &evaluatorProductionsBuilder{
		baseBuilder: newBaseBuilder("productions"),
		productions: p,
	}
}

type evaluatorProductionsBuilder struct {
	*baseBuilder
	productions *config.EvaluatorProductions
}

func (b *evaluatorProductionsBuilder) propAt(idx interface{}) (objRef, error) {
	err := checkIndexRange(idx, len(b.productions.Values))
	if err != nil {
		return nil, err
	}
	p := &config.EvaluatorProduction{}
	b.productions.Values = append(b.productions.Values, p)
	return newEvaluatorProductionBuilder(p), nil
}

// newEvaluatorProductionBuilder returns a builder for single config.EvaluatorProduction instance.
func newEvaluatorProductionBuilder(p *config.EvaluatorProduction) *evaluatorProductionBuilder {
	return &evaluatorProductionBuilder{
		baseBuilder: newBaseBuilder("production"),
		production:  p,
	}
}

type evaluatorProductionBuilder struct {
	*baseBuilder
	production *config.EvaluatorProduction
}

func (b *evaluatorProductionBuilder) prop(id int64, name string) (objRef, error) {
	field := config.NewStructField(id, name)
	builder := newDynValueBuilder(field.Ref)
	switch name {
	case "match":
		b.production.Match = field
		return builder, nil
	// allow for a singleton decision
	case "decision", "decisionRef", "output":
		outDec := b.production.OutputDecision
		if outDec == nil {
			outDec = &config.OutputDecision{}
			b.production.OutputDecision = outDec
		}
		switch name {
		case "decision":
			outDec.Decision = field
		case "decisionRef":
			outDec.Reference = field
		case "output":
			outDec.Output = field
		}
		return builder, nil
	// or a list of decisions
	case "decisions":
		b.production.OutputDecisions = &config.OutputDecisions{
			ID:     id,
			Values: []*config.OutputDecision{},
		}
		return newOutputDecisionsBuilder(b.production.OutputDecisions), nil
	}
	return nil, noSuchProperty("production", name)
}

// newOutputDecisionsBuilder returns a builder for a list of output decisions to be emitted once
// a match prediate returns true.
func newOutputDecisionsBuilder(d *config.OutputDecisions) *outputDecisionsBuilder {
	return &outputDecisionsBuilder{
		baseBuilder:     newBaseBuilder("decisions"),
		outputDecisions: d,
	}
}

type outputDecisionsBuilder struct {
	*baseBuilder
	outputDecisions *config.OutputDecisions
}

func (b *outputDecisionsBuilder) propAt(idx interface{}) (objRef, error) {
	err := checkIndexRange(idx, len(b.outputDecisions.Values))
	if err != nil {
		return nil, err
	}
	outDec := &config.OutputDecision{}
	b.outputDecisions.Values = append(b.outputDecisions.Values, outDec)
	return newOutputDecisionBuilder(outDec), nil
}

// newOutputDecisionBuilder returns a builder for a single config.OutputDecision.
func newOutputDecisionBuilder(outDec *config.OutputDecision) *outputDecisionBuilder {
	return &outputDecisionBuilder{
		baseBuilder:    newBaseBuilder("outputDecision"),
		outputDecision: outDec,
	}
}

type outputDecisionBuilder struct {
	*baseBuilder
	outputDecision *config.OutputDecision
}

func (b *outputDecisionBuilder) prop(id int64, name string) (objRef, error) {
	field := config.NewStructField(id, name)
	builder := newDynValueBuilder(field.Ref)
	switch name {
	case "decision":
		b.outputDecision.Decision = field
		return builder, nil
	case "decisionRef":
		b.outputDecision.Reference = field
		return builder, nil
	case "output":
		b.outputDecision.Output = field
		return builder, nil
	}
	return nil, noSuchProperty("outputDecision", name)
}

// newInstanceBuilder produces a builder for a config.Instance object.
func newInstanceBuilder(inst *config.Instance) *instanceBuilder {
	return &instanceBuilder{
		baseBuilder: newBaseBuilder("instance"),
		instance:    inst,
	}
}

type instanceBuilder struct {
	*baseBuilder
	instance *config.Instance
}

// id is an implementation of the objRef interface method.
func (b *instanceBuilder) id(id int64) {
	b.instance.ID = id
}

// prop returns a builder for the config.Instance fields as appropriate.
func (b *instanceBuilder) prop(id int64, name string) (objRef, error) {
	field := config.NewStructField(id, name)
	builder := newDynValueBuilder(field.Ref)
	switch name {
	case "apiVersion":
		b.instance.APIVersion = field
		return builder, nil
	case "description":
		b.instance.Description = field
		return builder, nil
	case "kind":
		b.instance.Kind = field
		return builder, nil
	case "metadata":
		sv := config.NewStructValue()
		field.Ref.Value = sv
		b.instance.Metadata = field
		builder.sb = newStructBuilder(sv)
		return builder, nil
	case "rules":
		lv := config.NewListValue()
		field.Ref.Value = lv
		b.instance.Rules = field
		builder.lb = newListBuilder(lv)
		return builder, nil
	case "selector":
		b.instance.Selector = &config.Selector{ID: id}
		return newSelectorBuilder(b.instance.Selector), nil
	}
	return nil, noSuchProperty("instance", name)
}

// newSelectorBuilder returns a builder for config.Selector instances.
func newSelectorBuilder(sel *config.Selector) *selectorBuilder {
	return &selectorBuilder{
		baseBuilder: newBaseBuilder("selector"),
		sel:         sel,
	}
}

type selectorBuilder struct {
	*baseBuilder
	sel *config.Selector
}

// prop returns builders for selector matcher fields.
func (b *selectorBuilder) prop(id int64, name string) (objRef, error) {
	switch name {
	case "matchLabels":
		b.sel.MatchLabels = &config.MatchLabels{
			ID:       id,
			Matchers: []*config.LabelMatcher{},
		}
		return newMatchLabelsBuilder(b.sel.MatchLabels), nil
	case "matchExpressions":
		b.sel.MatchExpressions = &config.MatchExpressions{
			ID:       id,
			Matchers: []*config.ExprMatcher{},
		}
		return newMatchExpressionsBuilder(b.sel.MatchExpressions), nil
	default:
		return nil, noSuchProperty("selector", name)
	}
}

// newMatchLabelsBuilder returns a builder for matchLabels.
func newMatchLabelsBuilder(labels *config.MatchLabels) *matchLabelsBuilder {
	return &matchLabelsBuilder{
		baseBuilder: newBaseBuilder("matchLabels"),
		labels:      labels,
	}
}

type matchLabelsBuilder struct {
	*baseBuilder
	labels *config.MatchLabels
}

// prop returns a builder for the key, value pairs expected by the matchLabels object.
func (b *matchLabelsBuilder) prop(id int64, name string) (objRef, error) {
	kv := config.NewDynValue(id, config.StringValue(name))
	val := config.NewEmptyDynValue()
	lbl := &config.LabelMatcher{Key: kv, Value: val}
	b.labels.Matchers = append(b.labels.Matchers, lbl)
	return newDynValueBuilder(val), nil
}

// newMatchExpressionsBuilder returns a builder for the list of match expressions which
// perform set-like tests on key values.
func newMatchExpressionsBuilder(exprs *config.MatchExpressions) *matchExpressionsBuilder {
	return &matchExpressionsBuilder{
		baseBuilder: newBaseBuilder("matchExpressions"),
		exprs:       exprs,
	}
}

type matchExpressionsBuilder struct {
	*baseBuilder
	exprs *config.MatchExpressions
}

// propAt returns a builder for a single expression matcher within the matchExpressions list.
func (b *matchExpressionsBuilder) propAt(idx interface{}) (objRef, error) {
	err := checkIndexRange(idx, len(b.exprs.Matchers))
	if err != nil {
		return nil, err
	}
	m := &config.ExprMatcher{}
	b.exprs.Matchers = append(b.exprs.Matchers, m)
	return newExprMatcherBuilder(m), nil
}

// newExprMatcher returns a builder for a matchExpressions set-like operation.
func newExprMatcherBuilder(m *config.ExprMatcher) *exprMatcherBuilder {
	return &exprMatcherBuilder{
		baseBuilder: newBaseBuilder("exprMatcher"),
		match:       m,
	}
}

type exprMatcherBuilder struct {
	*baseBuilder
	match *config.ExprMatcher
}

// prop implements the objRef interface method and sets the values supported by the
// matchExpressions.
func (b *exprMatcherBuilder) prop(id int64, name string) (objRef, error) {
	switch name {
	case "key":
		b.match.Key = config.NewDynValue(id, nil)
		return newDynValueBuilder(b.match.Key), nil
	case "operator":
		b.match.Operator = config.NewDynValue(id, nil)
		return newDynValueBuilder(b.match.Operator), nil
	case "values":
		lv := config.NewListValue()
		b.match.Values = config.NewDynValue(id, lv)
		db := newDynValueBuilder(b.match.Values)
		db.lb = newListBuilder(lv)
		return db, nil
	default:
		return nil, noSuchProperty("exprMatcher", name)
	}
}

// newStructBuilder returns a builder for dynamic values of struct type.
func newStructBuilder(sv *config.StructValue) *structBuilder {
	return &structBuilder{
		baseBuilder: newBaseBuilder("struct"),
		structVal:   sv,
	}
}

type structBuilder struct {
	*baseBuilder
	structVal *config.StructValue
}

// prop returns a builder for a struct property.
func (b *structBuilder) prop(id int64, name string) (objRef, error) {
	field := config.NewStructField(id, name)
	b.structVal.Fields = append(b.structVal.Fields, field)
	return newDynValueBuilder(field.Ref), nil
}

// newListBuilder returns a builder for a dynamic value of list type.
func newListBuilder(lv *config.ListValue) *listBuilder {
	return &listBuilder{
		baseBuilder: newBaseBuilder("list"),
		listVal:     lv,
	}
}

type listBuilder struct {
	*baseBuilder
	listVal *config.ListValue
}

// propAt returns a builder for a list element at the given index.
func (b *listBuilder) propAt(idx interface{}) (objRef, error) {
	err := checkIndexRange(idx, len(b.listVal.Entries))
	if err != nil {
		return nil, err
	}
	dyn := config.NewEmptyDynValue()
	b.listVal.Entries = append(b.listVal.Entries, dyn)
	return newDynValueBuilder(dyn), nil
}

// newDynValueBuilder returns a builder for a config.DynValue.
func newDynValueBuilder(dyn *config.DynValue) *dynValueBuilder {
	return &dynValueBuilder{
		dyn: dyn,
	}
}

type dynValueBuilder struct {
	dyn *config.DynValue
	lb  *listBuilder
	sb  *structBuilder
}

// id sets the source element id of the dyn literal.
func (b *dynValueBuilder) id(id int64) {
	b.dyn.ID = id
}

// assign will set the value of the config.DynValue.
//
// If the builder had previously been configured to produce list or struct values, the function
// returns an error.
func (b *dynValueBuilder) assign(val interface{}) error {
	if b.sb != nil {
		return valueNotAssignableToType("struct", val)
	}
	if b.lb != nil {
		return valueNotAssignableToType("list", val)
	}
	var vn config.ValueNode
	switch v := val.(type) {
	case bool:
		vn = config.BoolValue(v)
	case float64:
		vn = config.DoubleValue(v)
	case int64:
		vn = config.IntValue(v)
	case string:
		vn = config.StringValue(v)
	case uint64:
		vn = config.UintValue(v)
	case config.NullValue:
		vn = v
	default:
		return valueNotAssignableToType("dyn", v)
	}
	b.dyn.Value = vn
	return nil
}

// prop returns a builder for a struct field.
//
// If the dyn builder was previously configured as a list builder, the function will error.
func (b *dynValueBuilder) prop(id int64, name string) (objRef, error) {
	if b.lb != nil {
		return nil, typeNotAssignableToType("list", "struct")
	}
	if b.sb == nil {
		sv := config.NewStructValue()
		b.dyn.Value = sv
		b.sb = newStructBuilder(sv)
	}
	return b.sb.prop(id, name)
}

// propAt returns a builder for an element within a list value.
//
// If the dyn builder was previously configured as a struct, this function will error.
func (b *dynValueBuilder) propAt(idx interface{}) (objRef, error) {
	if b.sb != nil {
		return nil, typeNotAssignableToType("struct", "list")
	}
	if b.lb == nil {
		lv := config.NewListValue()
		b.dyn.Value = lv
		b.lb = newListBuilder(lv)
	}
	return b.lb.propAt(idx)
}

// helper methods for formatting builder-related error messages.

func checkIndexRange(idx interface{}, sz int) error {
	i, ok := idx.(int)
	if !ok {
		return invalidIndexType("int", idx)
	}
	if i < 0 || i > sz {
		return indexOutOfRange(idx, sz)
	}
	return nil
}

func typeNotAssignableToType(typeName, valType string) error {
	return fmt.Errorf("type not assignable to target: target=%v, type=%s", typeName, valType)
}

func valueNotAssignableToType(typeName string, val interface{}) error {
	return fmt.Errorf("type not assignable to target: target=%s, type=%T", typeName, val)
}

func noSuchProperty(typeName, prop string) error {
	return fmt.Errorf("no such property: type=%s, property=%s", typeName, prop)
}

func indexOutOfRange(idx interface{}, len int) error {
	return fmt.Errorf("index out of range: index=%v, len=%d", idx, len)
}

func invalidIndexType(typeName string, idx interface{}) error {
	return fmt.Errorf("invalid index type: index-type:%s, argument=%T", typeName, idx)
}
