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
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types/ref"

	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

// NewTemplate produces an empty policy Template instance.
func NewTemplate() *Template {
	return &Template{
		Metadata:  NewTemplateMetadata(),
		Evaluator: NewEvaluator(),
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
}

// NewRuleTypes returns an Open API Schema-based type-system which is CEL compatible.
func NewRuleTypes(kind string, schema *OpenAPISchema) *RuleTypes {
	// Note, if the schema indicates that it's actually based on another proto
	// then prefer the proto definition. For expressions in the proto, a new field
	// annotation will be needed to indicate the expected environment and type of
	// the expression.
	return &RuleTypes{
		ruleSchemaTypes: newSchemaTypeProvider(kind, schema),
		Schema:          schema,
	}
}

// RuleTypes extends the CEL ref.TypeProvider interface and provides an Open API Schema-based
// type-system.
type RuleTypes struct {
	ref.TypeProvider
	Schema          *OpenAPISchema
	ruleSchemaTypes *schemaTypeProvider
}

// EnvOptions returns a set of cel.EnvOption values which includes the Template's declaration set
// as well as a custom ref.TypeProvider.
//
// Note, the standard declaration set includes 'rule' which is defined as the top-level rule-schema
// type if one is configured.
//
// If the RuleTypes value is nil, an empty []cel.EnvOption set is returned.
func (rt *RuleTypes) EnvOptions(tp ref.TypeProvider) []cel.EnvOption {
	if rt == nil {
		return []cel.EnvOption{}
	}
	return []cel.EnvOption{
		cel.CustomTypeProvider(&RuleTypes{
			TypeProvider:    tp,
			Schema:          rt.Schema,
			ruleSchemaTypes: rt.ruleSchemaTypes,
		}),
		cel.Declarations(
			decls.NewIdent("rule", rt.ruleSchemaTypes.root.ExprType(), nil),
		),
	}
}

// FindType attempts to resolve the typeName provided from the template's rule-schema, or if not
// from the embedded ref.TypeProvider.
//
// FindType overrides the default type-finding behavior of the embedded TypeProvider.
//
// Note, when the type name is based on the Open API Schema, the name will reflect the object path
// where the type definition appears.
func (rt *RuleTypes) FindType(typeName string) (*exprpb.Type, bool) {
	if rt == nil {
		return nil, false
	}
	simple, found := simpleExprTypes[typeName]
	if found {
		return simple, true
	}
	st, found := rt.ruleSchemaTypes.types[typeName]
	if found {
		return st.ExprType(), true
	}
	return rt.TypeProvider.FindType(typeName)
}

// FindFieldType returns a field type given a type name and field name, if found.
//
// Note, the type name for an Open API Schema type is likely to be its qualified object path.
// If, in the future an object instance rather than a type name were provided, the field
// resolution might more accurately reflect the expected type model. However, in this case
// concessions were made to align with the existing CEL interfaces.
func (rt *RuleTypes) FindFieldType(typeName, fieldName string) (*ref.FieldType, bool) {
	st, found := rt.ruleSchemaTypes.types[typeName]
	if !found {
		return rt.TypeProvider.FindFieldType(typeName, fieldName)
	}
	f, found := st.fields[fieldName]
	if found {
		return &ref.FieldType{
			// TODO: Provide IsSet, GetFrom which build upon maps
			Type: f.ExprType(),
		}, true
	}
	// This could be a dynamic map.
	if st.ModelType() == MapType && !st.isObject() {
		return &ref.FieldType{
			// TODO: Provide IsSet, GetFrom which build upon maps
			Type: st.elemType.ExprType(),
		}, true
	}
	return nil, false
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
func NewTerm(name string, expr *cel.Ast) *Term {
	return &Term{
		Name:       name,
		Expr:       expr,
		InputTerms: make(map[string]*Term),
	}
}

// Term is a template-local variable whose name may shadow names in the Template environment and
// which may depend on preceding terms as input.
type Term struct {
	Name       string
	InputTerms map[string]*Term
	Expr       *cel.Ast
}

// NewProduction returns an empty instance of a Production rule which minimally contains a single
// Decision.
func NewProduction(match *cel.Ast) *Production {
	return &Production{
		Match:     match,
		Decisions: []*Decision{},
	}
}

// Production describes an match-decision pair where the match, if set, indicates whether the
// Decision is applicable, and the decision indicates its name and output value.
type Production struct {
	Match     *cel.Ast
	Decisions []*Decision
}

// NewDecision returns an empty Decision instance.
func NewDecision() *Decision {
	return &Decision{}
}

// Decision contains a decision name, or reference to a decision name, and an output expression.
type Decision struct {
	Decision  string
	Reference *cel.Ast
	Output    *cel.Ast
}
