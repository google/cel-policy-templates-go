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

func NewTemplate() *Template {
	return &Template{
		Metadata:  NewTemplateMetadata(),
		Evaluator: NewEvaluator(),
	}
}

type Template struct {
	APIVersion  string
	Kind        string
	Metadata    *TemplateMetadata
	Description string
	RuleTypes   *RuleTypes
	Validator   *Evaluator
	Evaluator   *Evaluator
}

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

type RuleTypes struct {
	ref.TypeProvider
	Schema          *OpenAPISchema
	ruleSchemaTypes *schemaTypeProvider
}

func (rt *RuleTypes) Declarations() cel.EnvOption {
	return cel.Declarations(
		decls.NewIdent("rule", rt.ruleSchemaTypes.root.ExprType(), nil),
	)
}

func (rt *RuleTypes) Types(tp ref.TypeProvider) cel.EnvOption {
	return cel.CustomTypeProvider(&RuleTypes{
		TypeProvider:    tp,
		Schema:          rt.Schema,
		ruleSchemaTypes: rt.ruleSchemaTypes,
	})
}

func (rt *RuleTypes) FindType(typeName string) (*exprpb.Type, bool) {
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

func NewTemplateMetadata() *TemplateMetadata {
	return &TemplateMetadata{
		Properties: make(map[string]string),
	}
}

type TemplateMetadata struct {
	UID        string
	Name       string
	Namespace  string
	PluralName string
	Properties map[string]string
}

func NewEvaluator() *Evaluator {
	return &Evaluator{
		Terms:       []*Term{},
		Productions: []*Production{},
	}
}

type Evaluator struct {
	Environment string
	Terms       []*Term
	Productions []*Production
}

func NewTerm(name string, expr *cel.Ast) *Term {
	return &Term{
		Name:       name,
		Expr:       expr,
		InputTerms: make(map[string]*Term),
	}
}

type Term struct {
	Name       string
	InputTerms map[string]*Term
	Expr       *cel.Ast
}

func NewProduction(match *cel.Ast) *Production {
	return &Production{
		Match:     match,
		Decisions: []*Decision{},
	}
}

type Production struct {
	Match     *cel.Ast
	Decisions []*Decision
}

func NewDecision() *Decision {
	return &Decision{}
}

type Decision struct {
	Decision  string
	Reference *cel.Ast
	Output    *cel.Ast
}
