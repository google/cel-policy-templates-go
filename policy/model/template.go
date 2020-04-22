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

	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

func NewCompiledTemplate() *CompiledTemplate {
	return &CompiledTemplate{
		Metadata:  NewCompiledMetadata(),
		Validator: NewCompiledEvaluator(),
		Evaluator: NewCompiledEvaluator(),
	}
}

type CompiledTemplate struct {
	APIVersion  string
	Kind        string
	Metadata    *CompiledMetadata
	Description string
	RuleTypes   *RuleTypes
	Validator   *CompiledEvaluator
	Evaluator   *CompiledEvaluator
}

func NewRuleTypes(kind string, schema *OpenAPISchema) *RuleTypes {
	return &RuleTypes{
		typeProvider: newSchemaTypeProvider(kind, schema),
		Schema:       schema,
	}
}

type RuleTypes struct {
	Schema       *OpenAPISchema
	typeProvider *schemaTypeProvider
}

func (rt *RuleTypes) FindType(typeName string) (*exprpb.Type, bool) {
	simple, found := simpleExprTypes[typeName]
	if found {
		return simple, true
	}
	st, found := rt.typeProvider.types[typeName]
	if found {
		return st.ExprType(), true
	}
	return nil, false
}

func (rt *RuleTypes) FindFieldType(typeName, fieldName string) (*ref.FieldType, bool) {
	st, found := rt.typeProvider.types[typeName]
	if !found {
		return nil, false
	}
	f, found := st.fields[fieldName]
	if found {
		return &ref.FieldType{
			// TODO: Provide IsSet, GetFrom which build upon maps
			Type: f.ExprType(),
		}, true
	}
	if st.CommonType() == "map" {
		return &ref.FieldType{
			// TODO: Provide IsSet, GetFrom which build upon maps
			Type: st.elemType.ExprType(),
		}, true
	}
	return nil, false
}

// TODO: implement TypeAdapter interface.

func NewCompiledMetadata() *CompiledMetadata {
	return &CompiledMetadata{
		Properties: make(map[string]string),
	}
}

type CompiledMetadata struct {
	UID        string
	Name       string
	Namespace  string
	PluralName string
	Properties map[string]string
}

func NewCompiledEvaluator() *CompiledEvaluator {
	return &CompiledEvaluator{
		Terms:       []*CompiledTerm{},
		Productions: []*CompiledProduction{},
	}
}

type CompiledEvaluator struct {
	Environment string
	Terms       []*CompiledTerm
	Productions []*CompiledProduction
}

func NewCompiledTerm() *CompiledTerm {
	return &CompiledTerm{
		InputTerms: make(map[string]*CompiledTerm),
	}
}

type CompiledTerm struct {
	Name       string
	InputTerms map[string]*CompiledTerm
	Expr       *cel.Ast
}

func NewCompiledProduction() *CompiledProduction {
	return &CompiledProduction{
		Decisions: []*CompiledDecision{},
	}
}

type CompiledProduction struct {
	Match     *cel.Ast
	Decisions []*CompiledDecision
}

func NewCompiledDecision() *CompiledDecision {
	return &CompiledDecision{}
}

type CompiledDecision struct {
	Decision  string
	Reference *cel.Ast
	Output    *cel.Ast
}
