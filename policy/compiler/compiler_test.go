// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package compiler

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-policy-templates-go/policy/model"
	"github.com/google/cel-policy-templates-go/policy/parser"
)

func TestCompiler_Template(t *testing.T) {
	tests := []struct {
		ID  string
		In  string
		Out string
	}{
		{
			ID: "canonical",
			In: `apiVersion: policy.acme.co/v1
kind: PolicyTemplate
metadata:
  name: MultilineTemplate
description: >
  Policy for configuring greetings and farewells.
schema:
  type: object
  properties:
    greeting:
      type: string
    farewell:
      type: string
validator:
  terms:
    hi: rule.greeting
    bye: rule.farewell
    uint: 9223372036854775808
  productions:
    - match: hi == '' && bye == ''
      message: at least one property must be set on the rule.
    - match: hi.startsWith("Goodbye")
      message: greeting starts with a farewell word
      details: hi
evaluator:
  terms:
    hi: rule.greeting
    bye: rule.farewell
  productions:
    - match: hi != '' && bye == ''
      decision: policy.acme.welcome
      output: hi
    - match: bye != '' && hi == ''
      decision: policy.acme.depart
      output: bye
    - match: hi != '' && bye != ''
      decisions:
        - decision: policy.acme.welcome
          output: hi
        - decision: policy.acme.depart
          output: bye`,
		},
	}

	reg := &registry{
		schemas: map[string]*model.OpenAPISchema{},
	}
	reg.RegisterSchema("#openAPISchema", model.SchemaDef)
	reg.RegisterSchema("#templateSchema", model.TemplateSchema)
	comp := &Compiler{reg: reg}
	for _, tst := range tests {
		src := model.StringSource(tst.In, tst.ID)
		pv, errs := parser.ParseYaml(src)
		cpt, errs := comp.CompileTemplate(src, pv)
		if len(errs.GetErrors()) > 0 {
			t.Fatal(errs.ToDisplayString())
		}
		t.Logf("%v", cpt)
	}
}

type registry struct {
	schemas map[string]*model.OpenAPISchema
}

func (r *registry) FindSchema(name string) (*model.OpenAPISchema, bool) {
	s, found := r.schemas[name]
	return s, found
}

func (r *registry) RegisterSchema(name string, schema *model.OpenAPISchema) error {
	r.schemas[name] = schema
	return nil
}

func (r *registry) FindEnv(name string) (*cel.Env, bool) {
	return nil, false
}

func (r *registry) RegisterEnv(name string, e *cel.Env) error {
	return nil
}
