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
	"strings"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-policy-templates-go/policy/model"
	"github.com/google/cel-policy-templates-go/policy/parser"
)

func TestCompiler_Template(t *testing.T) {
	tests := []struct {
		ID  string
		In  string
		Err string
	}{
		{
			ID: "canonical",
			In: canonicalTemplate,
		},
		{
			ID: "empty_evaluator",
			In: `apiVersion: policy.acme.co/v1
kind: PolicyTemplate
metadata:
  name: NoEvaluatorTemplate
description: >
  Template that with an empty evaluator and validator
validator:
  terms:
    noop: ""
  productions:
    - match: noop
evaluator:`,
			Err: `
     ERROR: empty_evaluator:11:7: missing required field(s): [message]
      |     - match: noop
      | ......^
     ERROR: empty_evaluator:12:11: value not assignable to schema type: value=null_type, schema=map
      | evaluator:
      | ..........^
     ERROR: empty_evaluator:9:12: Syntax error: mismatched input '<EOF>' expecting {'[', '{', '(', '.', '-', '!', 'true', 'false', 'null', NUM_FLOAT, NUM_INT, NUM_UINT, STRING, BYTES, IDENTIFIER}
      |     noop: ""
      | ...........^
     ERROR: empty_evaluator:11:14: expected bool match result, found: !error!
      |     - match: noop
      | .............^
     ERROR: empty_evaluator:12:11: expected map type, found: null_type
      | evaluator:
      | ..........^`,
		},
		{
			ID: "errant",
			In: `apiVersion: policy.acme.co/v1
metadata:
  name: ErrantTemplate
  lastModified: 2020-04-28T21:27:00
description: >
  Policy for configuring greetings and farewells.
schema:
  type: object
  properties:
    greeting:
      type: string
    farewell:
      type: string
      enum: [1, 3.2, false, "okay"]
validator:
  terms:
    hi: rule.grating
    bye: rule.farewell
    uintVal: 9223372036854775808
    uintVal: 9223372036854775809
  productions:
    - match: hi == '' && byte == ''
      message: at least one property must be set on the rule.
evaluator:
  terms:
    hi: |
      bye != ''
      ? rule.greting
      : ''
    bye: rule.farewell
  productions:
    - match: hi != '' && bye == ''
      decision: policy.acme.welcome
      output: hi`,
			Err: `
     ERROR: errant:14:14: value not assignable to schema type: value=int, schema=string
      |       enum: [1, 3.2, false, "okay"]
      | .............^
     ERROR: errant:14:17: value not assignable to schema type: value=double, schema=string
      |       enum: [1, 3.2, false, "okay"]
      | ................^
     ERROR: errant:14:22: value not assignable to schema type: value=bool, schema=string
      |       enum: [1, 3.2, false, "okay"]
      | .....................^
     ERROR: errant:20:5: field redeclaration error: uintVal
      |     uintVal: 9223372036854775809
      | ....^
     ERROR: errant:1:1: missing required field(s): [kind]
      | apiVersion: policy.acme.co/v1
      | ^
     ERROR: errant:17:13: undefined field 'grating'
      |     hi: rule.grating
      | ............^
     ERROR: errant:22:26: undeclared reference to 'byte' (in container '')
      |     - match: hi == '' && byte == ''
      | .........................^
     ERROR: errant:27:7: undeclared reference to 'bye' (in container '')
      |       bye != ''
      | ......^
     ERROR: errant:28:13: undefined field 'greting'
      |       ? rule.greting
      | ............^`,
		},
	}

	reg := &registry{
		schemas: map[string]*model.OpenAPISchema{},
	}
	reg.RegisterSchema("#openAPISchema", model.SchemaDef)
	reg.RegisterSchema("#templateSchema", model.TemplateSchema)
	comp := &Compiler{reg: reg}
	for _, tc := range tests {
		tst := tc
		t.Run(tst.ID, func(tt *testing.T) {
			src := model.StringSource(tst.In, tst.ID)
			pv, errs := parser.ParseYaml(src)
			if len(errs.GetErrors()) > 0 {
				tt.Fatal(errs.ToDisplayString())
			}
			_, errs = comp.CompileTemplate(src, pv)
			dbgErr := errs.ToDisplayString()
			if !cmp(tst.Err, dbgErr) {
				tt.Fatalf("Got %v, expected error: %s", dbgErr, tst.Err)
			}
		})
	}
}

func TestCompiler_Instance(t *testing.T) {
	tests := []struct {
		ID  string
		In  string
		Err string
	}{
		{
			ID: `canonical`,
			In: `apiVersion: policy.acme.co/v1
kind: GreetingPolicy
metadata:
  name: seasons-greetings
selector:
  matchLabels:
    env: prod
  matchExpressions:
    - {key: "trace", operator: "DoesNotExist"}
    - {key: "debug", operator: "In", values: ["false", "justified"]}
rules:
  - greeting: "Hello"
  - farewell: "Farewell"
  - greeting: "You survived Y2K!"
    computer_greeting: WUFZIFkySyE=
    start_date: "2000-01-01T00:00:00Z"
    end_date: "2000-01-07T00:00:00Z"
    details:
      gone: [1999]
      next: [2038]
  - greeting: "Happy New Year's!"
    conditions:
      - description: Ring in the New Year.
        expression: >
          request.time.getMonth() == 0 &&
          request.time.getDate() == 1" `,
		},
		{
			ID: `errant`,
			In: `apiVersion: policy.acme.co/v1
kind: GreetingPolicy
metadata:
  name: errant-greetings
selector:
  matchLabels:
  matchExpressions:
    - {key: "env", operator: "NotIn", values: ["test", "staging"]}
    - {key: "env", operator: "In", values: [["test"]]}
    - {key: "trace", operator: "DoesNotExists"}
rules:
  - greeting: "Goodbye"
  - farewell: "Hello"
  - greeting: "Happy New Year's!"
    conditions:
      - description: Ring in the New Year.
        expression: >
          request.time.getMonth() == 0 &&
          request.time.getDate() == 1" `,
			Err: `
        ERROR: errant:6:15: value not assignable to schema type: value=null_type, schema=map
        |   matchLabels:
        | ..............^
        ERROR: errant:10:33: invalid enum value: DoesNotExists. must be one of: [DoesNotExist Exists In NotIn]
        |     - {key: "trace", operator: "DoesNotExists"}
        | ................................^
        ERROR: errant:13:16: invalid enum value: Hello. must be one of: [Aloha Adieu Bye Farewell true]
        |   - farewell: "Hello"
        | ...............^
        ERROR: errant:6:15: expected map type, found: null_type
        |   matchLabels:
        | ..............^
        ERROR: errant:9:45: expected primitive type, found=list
        |     - {key: "env", operator: "In", values: [["test"]]}
        | ............................................^`,
		},
	}

	reg := &registry{
		schemas:   map[string]*model.OpenAPISchema{},
		templates: map[string]*model.Template{},
	}
	reg.RegisterSchema("#openAPISchema", model.SchemaDef)
	reg.RegisterSchema("#templateSchema", model.TemplateSchema)
	comp := &Compiler{reg: reg}
	tmplSrc := model.StringSource(canonicalTemplate, "canonicalTemplate")
	tmplAst, _ := parser.ParseYaml(tmplSrc)
	tmpl, _ := comp.CompileTemplate(tmplSrc, tmplAst)
	reg.RegisterTemplate(tmpl.Metadata.Name, tmpl)

	for _, tst := range tests {
		src := model.StringSource(tst.In, tst.ID)
		pv, errs := parser.ParseYaml(src)
		if len(errs.GetErrors()) > 0 {
			t.Fatal(errs.ToDisplayString())
		}
		_, errs = comp.CompileInstance(src, pv)
		dbgErr := errs.ToDisplayString()
		if !cmp(tst.Err, dbgErr) {
			t.Fatalf("Got %v, expected error: %s", dbgErr, tst.Err)
		}
	}
}

type registry struct {
	schemas   map[string]*model.OpenAPISchema
	templates map[string]*model.Template
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
	if name == "standard" {
		e, _ := cel.NewEnv()
		return e, true
	}
	return nil, false
}

func (*registry) RegisterEnv(name string, e *cel.Env) error {
	return nil
}

func (r *registry) FindTemplate(name string) (*model.Template, bool) {
	tmpl, found := r.templates[name]
	return tmpl, found
}

func (r *registry) RegisterTemplate(name string, tmpl *model.Template) error {
	r.templates[name] = tmpl
	return nil
}

func cmp(a string, e string) bool {
	a = strings.Replace(a, " ", "", -1)
	a = strings.Replace(a, "\n", "", -1)
	a = strings.Replace(a, "\t", "", -1)

	e = strings.Replace(e, " ", "", -1)
	e = strings.Replace(e, "\n", "", -1)
	e = strings.Replace(e, "\t", "", -1)

	return a == e
}

var (
	canonicalTemplate = `
apiVersion: policy.acme.co/v1
kind: PolicyTemplate
metadata:
  name: GreetingPolicy
description: >
  Policy for configuring greetings and farewells.
schema:
  type: object
  properties:
    greeting:
      type: string
    farewell:
      type: string
      enum: ["Aloha", "Adieu", "Bye", "Farewell", !txt true]
    computer_greeting:
      type: string
      format: byte
    start_date:
      type: string
      format: date-time
    end_date:
      type: string
      format: date-time
    details:
      type: object
      default: {gone: [], next: []}
      additionalProperties:
        type: array
        items:
          type: integer

    conditions:
      type: array
      items:
        type: object
        metadata:
          protoRef: google.type.Expr
          resultType: bool
          environment: standard
        required:
          - expression
          - description
        properties:
          expression:
            type: string
          title:
            type: string
          description:
            type: string
          location:
            type: string

  additionalProperties:
    type: string
validator:
  environment: standard
  terms:
    hi: rule.greeting
    bye: rule.farewell
    both: hi == 'aloha' && bye == 'aloha'
    doubleVal: -42.42
    emptyNullVal:
    emptyQuotedVal: !txt ""
    falseVal: false
    intVal: -42
    nullVal: null
    plainTxtVal: !txt plain text
    trueVal: true
    uintVal: 9223372036854775808
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
          output: bye`
)
