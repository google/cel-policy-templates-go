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
	"fmt"
	"strings"
	"testing"

	"github.com/google/cel-policy-templates-go/policy/limits"
	"github.com/google/cel-policy-templates-go/policy/model"
	"github.com/google/cel-policy-templates-go/policy/parser"
	"github.com/google/cel-policy-templates-go/policy/runtime"
	"github.com/google/cel-policy-templates-go/test"

	"github.com/google/cel-go/cel"
	"gopkg.in/yaml.v3"
)

func TestCompiler(t *testing.T) {
	tr := test.NewReader("../../test/testdata")
	tests, err := tr.ReadCases("compile")
	if err != nil {
		t.Fatal(err)
	}

	stdEnv, _ := cel.NewEnv(test.Decls)
	reg := model.NewRegistry(stdEnv)
	reg.SetEnv("", model.NewEnv(""))
	reg.SetSchema("#address_type", addressSchema)
	limits := limits.NewLimits()
	limits.RangeLimit = 1
	limits.EvaluatorTermLimit = 15
	limits.EvaluatorProductionLimit = 10
	limits.EvaluatorDecisionLimit = 4
	limits.ValidatorTermLimit = 20
	limits.ValidatorProductionLimit = 15
	limits.RuleLimit = 4
	limits.EvaluatorExprCostLimit = 100
	rtOpts := []runtime.TemplateOption{runtime.Functions(test.Funcs...)}
	comp := NewCompiler(reg, limits, rtOpts...)
	for _, tc := range tests {
		tst := tc
		t.Run(tst.ID, func(tt *testing.T) {
			pv, iss := parser.ParseYaml(tst.In)
			if iss.Err() != nil {
				tt.Fatal(iss.Err())
			}
			var tmpl *model.Template
			var env *model.Env
			if tst.Kind == "env" {
				env, iss = comp.CompileEnv(tst.In, pv)
			}
			if tst.Kind == "template" {
				tmpl, iss = comp.CompileTemplate(tst.In, pv)
			}
			if tst.Kind == "instance" {
				_, iss = comp.CompileInstance(tst.In, pv)
			}
			dbgErr := ""
			if iss.Err() != nil {
				dbgErr = iss.Err().Error()
			}
			if !cmp(tst.Err, dbgErr) {
				fmt.Println(dbgErr)
				tt.Fatalf("Got %v, expected error: %s", dbgErr, tst.Err)
			}
			if env != nil {
				err := reg.SetEnv(env.Name, env)
				if err != nil {
					tt.Fatal(err)
				}
			}
			if tmpl != nil {
				reg.SetTemplate(tmpl.Metadata.Name, tmpl)
			}
		})
	}
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
	env *cel.Env

	addressSchema     *model.OpenAPISchema
	addressSchemaYaml = `
type: object
properties:
  street:
    type: string
  city:
    type: string
  state:
    type: string
  country:
    type: string
  zip:
    type: integer
`
)

func init() {
	env, _ = cel.NewEnv(test.Decls)
	addressSchema = model.NewOpenAPISchema()
	err := yaml.Unmarshal([]byte(addressSchemaYaml), addressSchema)
	if err != nil {
		panic(err)
	}
}
