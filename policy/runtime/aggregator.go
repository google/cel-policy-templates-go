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
	"github.com/google/cel-policy-templates-go/policy/model"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/interpreter"
)

// Aggregator defines the mechanism by which CEL evaluations within evaluator production rules
// are accumulated into a named decision emitted by the template runtime.
//
// The aggregator starts with an initial decision and always only accumulates the previous value
// with the next. In this respect, the aggregator behaves like a continuous comprehension which
// is capable of indicating when to exit the comprehension by whether or not its marked final.
type Aggregator interface {
	DefaultDecision() model.DecisionValue

	Aggregate(cel.Program,
		interpreter.Activation,
		model.DecisionValue,
		model.Rule) (model.DecisionValue, error)
}

// NewAndAggregator returns a RuntimeOption which configures an ANDing aggregator for a given
// decision name.
func NewAndAggregator(name string) TemplateOption {
	return DecisionAggregator(
		name,
		&AndAggregator{
			name:   name,
			defDec: model.NewBoolDecisionValue(name, types.True),
		},
	)
}

// AndAggregator accumulates boolean results until either a false is encountered, or the policy
// set is completely evaluated.
type AndAggregator struct {
	name   string
	defDec *model.BoolDecisionValue
}

// DefaultDecision returns a boolean decision initialized to 'true'.
func (and *AndAggregator) DefaultDecision() model.DecisionValue {
	return model.NewBoolDecisionValue(and.name, types.True)
}

// Aggregate combines the previous decision with the current value from CEl evaluation.
//
// If the value is False, the decision is finalized as no additional information can change the
// aggregation result.
func (and *AndAggregator) Aggregate(prg cel.Program, vars interpreter.Activation,
	prev model.DecisionValue, rule model.Rule) (model.DecisionValue, error) {
	val, det, _ := prg.Eval(vars)
	prevBool := prev.(*model.BoolDecisionValue)
	decVal := prevBool.And(val)
	if decVal.Value() == types.False {
		decVal.Finalize(det, rule)
	}
	return decVal, nil
}

// NewCollectAggregator creates a new CollectAggregator which accumulates values emitted for
// the given decision name.
func NewCollectAggregator(name string) TemplateOption {
	return DecisionAggregator(
		name,
		&CollectAggregator{
			name:   name,
			defDec: model.NewListDecisionValue(name),
		},
	)
}

// CollectAggregator accumulates each value emitted for the given decision name into a list of
// values associated with the decision.
type CollectAggregator struct {
	name   string
	defDec *model.ListDecisionValue
}

// DefaultDecision produces a decision whose default decision value is empty set.
func (col *CollectAggregator) DefaultDecision() model.DecisionValue {
	return col.defDec
}

// Aggregate appends the value produced by evaluating the CEL program (if not error) with the
// previous values observed for the decision.
//
// Note: the collect aggregator does not quite follow CEL semantics with respect to list
// construction as the output decision value may include CEL types.Unknown values within it.
// It is up to the application to decide whether to error or resolve the unknowns.
func (col *CollectAggregator) Aggregate(prg cel.Program, vars interpreter.Activation,
	prev model.DecisionValue, rule model.Rule) (model.DecisionValue, error) {
	val, det, err := prg.Eval(vars)
	if err != nil {
		return nil, err
	}
	var prevList *model.ListDecisionValue
	if prev != col.defDec {
		prevList = prev.(*model.ListDecisionValue)
	} else {
		prevList = model.NewListDecisionValue(col.name)
	}
	prevList.Append(val, det, rule)
	return prevList, nil
}

// NewOrAggregator returns an OrAggregator which accumulates values into a boolean decision.
func NewOrAggregator(name string) TemplateOption {
	return DecisionAggregator(
		name,
		&OrAggregator{
			name:   name,
			defDec: model.NewBoolDecisionValue(name, types.False),
		},
	)
}

// OrAggregator accumulates boolean results until either a true is encountered, or the policy
// set is has been completely evaluated.
type OrAggregator struct {
	name   string
	defDec *model.BoolDecisionValue
}

// DefaultDecision produces a decision whose default decision value is 'false'.
func (or *OrAggregator) DefaultDecision() model.DecisionValue {
	return or.defDec
}

// Aggregate combines the value produced by the incoming CEL value with the previous value
// observed by the aggregator using CEL ORing semantics.
//
// If the value is true, the decision is finalized as no additional information can change the
// aggregation result.
func (or *OrAggregator) Aggregate(prg cel.Program, vars interpreter.Activation,
	prev model.DecisionValue, rule model.Rule) (model.DecisionValue, error) {
	val, det, _ := prg.Eval(vars)
	if val == types.False {
		return prev, nil
	}
	var prevBool *model.BoolDecisionValue
	if prev != or.defDec {
		prevBool = prev.(*model.BoolDecisionValue)
	} else {
		prevBool = model.NewBoolDecisionValue(or.name, types.False)
	}
	decVal := prevBool.Or(val)
	if decVal.Value() == types.True {
		decVal.Finalize(det, rule)
	}
	return decVal, nil
}
