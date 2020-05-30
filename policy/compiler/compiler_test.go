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
	"github.com/google/cel-policy-templates-go/test"

	"github.com/google/cel-go/cel"
)

func TestCompiler(t *testing.T) {
	tr := test.NewReader("../../test/testdata")
	tests, err := tr.ReadCases("compile")
	if err != nil {
		t.Fatal(err)
	}

	reg := &registry{
		schemas: map[string]*model.OpenAPISchema{
			"#openAPISchema":  model.SchemaDef,
			"#templateSchema": model.TemplateSchema,
			"#instanceSchema": model.InstanceSchema,
		},
		templates: map[string]*model.Template{},
	}
	limits := limits.NewLimits()
	limits.RangeLimit = 1
	comp := NewCompiler(reg, limits)
	for _, tc := range tests {
		tst := tc
		t.Run(tst.ID, func(tt *testing.T) {
			pv, iss := parser.ParseYaml(tst.In)
			if iss.Err() != nil {
				tt.Fatal(iss.Err())
			}
			var tmpl *model.Template
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
			if tmpl != nil {
				reg.templates[tmpl.Metadata.Name] = tmpl
			}
		})
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

func (r *registry) FindEnv(name string) (*cel.Env, bool) {
	if name == "" || name == "standard" {
		return env, true
	}
	return nil, false
}

func (r *registry) FindTemplate(name string) (*model.Template, bool) {
	tmpl, found := r.templates[name]
	return tmpl, found
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

var env *cel.Env

func init() {
	env, _ = cel.NewEnv(test.Decls)
}
