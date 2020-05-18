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

package model

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"
)

// NewTemplate produces an empty policy Template instance.
func NewTemplate(info *SourceInfo) *Template {
	return &Template{
		Metadata:  NewTemplateMetadata(),
		Evaluator: NewEvaluator(),
		Info:      info,
	}
}

// Template represents the compiled and type-checked policy template.
type Template struct {
	APIVersion  string
	Kind        string
	Metadata    *TemplateMetadata
	Description string
	RuleTypes   *RuleTypes
	Validator   *Evaluator
	Evaluator   *Evaluator
	Info        *SourceInfo
}

// NewTemplateMetadata returns an empty *TemplateMetadata instance.
func NewTemplateMetadata() *TemplateMetadata {
	return &TemplateMetadata{
		Properties: make(map[string]string),
	}
}

// TemplateMetadata contains the top-level information about the Template, including its name and
// namespace.
type TemplateMetadata struct {
	UID       string
	Name      string
	Namespace string

	// PluralMame is the plural form of the template name to use when managing a collection of
	// template instances.
	PluralName string

	// Properties contains an optional set of key-value information which external applications
	// might find useful.
	Properties map[string]string
}

// NewEvaluator returns an empty instance of a Template Evaluator.
func NewEvaluator() *Evaluator {
	return &Evaluator{
		Terms:       []*Term{},
		Productions: []*Production{},
	}
}

// Evaluator contains a set of production rules used to validate policy templates or
// evaluate template instances.
//
// The evaluator may optionally specify a named and versioned Environment as the basis for the
// variables and functions exposed to the CEL expressions within the Evaluator, and an optional
// set of terms.
//
// Terms are like template-local variables. Terms may rely on other terms which precede them.
// Term order matters, and no cycles are permitted among terms by design and convention.
type Evaluator struct {
	Environment string
	Terms       []*Term
	Productions []*Production
}

// NewTerm produces a named Term instance associated with a CEL Ast and a list of the input
// terms needed to evaluate the Ast successfully.
func NewTerm(id int64, name string, expr *cel.Ast) *Term {
	return &Term{
		ID:         id,
		Name:       name,
		Expr:       expr,
		InputTerms: make(map[string]*Term),
	}
}

// Term is a template-local variable whose name may shadow names in the Template environment and
// which may depend on preceding terms as input.
type Term struct {
	ID         int64
	Name       string
	InputTerms map[string]*Term
	Expr       *cel.Ast
}

// NewProduction returns an empty instance of a Production rule which minimally contains a single
// Decision.
func NewProduction(id int64, match *cel.Ast) *Production {
	return &Production{
		ID:        id,
		Match:     match,
		Decisions: []*Decision{},
	}
}

// Production describes an match-decision pair where the match, if set, indicates whether the
// Decision is applicable, and the decision indicates its name and output value.
type Production struct {
	ID        int64
	Match     *cel.Ast
	Decisions []*Decision
}

// NewDecision returns an empty Decision instance.
func NewDecision() *Decision {
	return &Decision{}
}

// Decision contains a decision name, or reference to a decision name, and an output expression.
type Decision struct {
	Name      string
	Reference *cel.Ast
	Output    *cel.Ast
}

// NewDecisionValue creates a new named decision with a value, and if configured appropriate a set
// of evaluation details which contain debug information about the evaluation of the output
// expression.
func NewDecisionValue(name string, val ref.Val, det *cel.EvalDetails) *DecisionValue {
	return &DecisionValue{
		Name:    name,
		Value:   val,
		Details: det,
	}
}

// DecisionValue represents a named decision and value.
//
// If the evaluation of the decision is performed with the cel.EvalOptions(cel.OptTrackState)
// option, the Details field will be non-nil and contain debug information about the expression
// evaluation.
type DecisionValue struct {
	RuleID  int64
	Name    string
	Value   ref.Val
	Details *cel.EvalDetails
}
