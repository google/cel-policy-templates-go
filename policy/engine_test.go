// Copyright 2019 Google LLC
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

package policy

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/interpreter"
	"github.com/google/cel-policy-templates-go/policy/model"
	"github.com/google/cel-policy-templates-go/policy/test"

	tpb "github.com/golang/protobuf/ptypes/timestamp"
)

type tc struct {
	name    string
	policy  string
	input   map[string]interface{}
	outputs []interface{}
	opts    []EngineOption
	e       string
}

type metadata struct {
	Resource      string
	Mode          string
	ResourceTypes []string
	Data          []string
}

type violation struct {
	Message string
	Details *metadata
}

func (v violation) String() string {
	return v.Message
}

type access struct {
	Deny  bool
	Allow bool
}

var (
	testCases = []tc{
		// Binauthz
		{
			name:   "binauthz_package_violations",
			policy: "binauthz",
			input: map[string]interface{}{
				"request.packages": []interface{}{
					map[string]interface{}{
						"name": "minted-fail",
						"provenance": map[string]interface{}{
							"valid":          true,
							"builder":        "build-secure",
							"submitted_code": true,
							"build_target":   "//mint:target_3",
							"is_mainline":    true,
							"branch_name":    "master",
						},
					},
					map[string]interface{}{
						"name": "unminted-fail",
						"provenance": map[string]interface{}{
							"valid":          true,
							"builder":        "build-insecure",
							"submitted_code": false,
							"build_target":   "//nonmint:target",
							"branch_name":    "dev",
						},
					},
				},
			},
			outputs: []interface{}{
				violation{
					Message: "package minted-fail: disallowed build target",
				},
				violation{
					Message: "package unminted-fail: not verifiably built",
				},
			},
		},
		// multiple ranges
		{
			name:   "multiple_ranges_behavior",
			policy: "multiple_ranges",
			input: map[string]interface{}{},
			outputs: []interface{}{
				"b", "c",
				"a", "c",
				"a", "b",
			},
			opts: []EngineOption{
				RangeLimit(2),
			},
		},
		// Sensitive Data
		{
			name:   "sensitive_data_prefix_same_location",
			policy: "sensitive_data",
			input: map[string]interface{}{
				"destination.ip":  "10.0.0.1",
				"origin.ip":       "10.0.0.1",
				"resource.name":   "/company/acme/secrets/doomsday-device",
				"resource.labels": map[string]string{},
			},
			outputs: []interface{}{},
		},
		{
			name:   "sensitive_data_prefix_diff_location",
			policy: "sensitive_data",
			input: map[string]interface{}{
				"destination.ip":  "10.0.0.1",
				"origin.ip":       "10.0.0.2",
				"resource.name":   "/company/acme/secrets/doomsday-device",
				"resource.labels": map[string]string{},
			},
			outputs: []interface{}{true},
		},
		{
			name:   "sensitive_data_label_same_location",
			policy: "sensitive_data",
			input: map[string]interface{}{
				"destination.ip": "10.0.0.1",
				"origin.ip":      "10.0.0.1",
				"resource.name":  "/company/acme/seems-normal/but-isnt",
				"resource.labels": map[string]string{
					"sensitivity": "secret",
				},
			},
			outputs: []interface{}{},
		},
		{
			name:   "sensitive_data_label_diff_location",
			policy: "sensitive_data",
			input: map[string]interface{}{
				"destination.ip": "10.0.0.2",
				"origin.ip":      "10.0.0.1",
				"resource.name":  "/company/acme/seems-normal/but-isnt",
				"resource.labels": map[string]string{
					"sensitivity": "secret",
				},
			},
			outputs: []interface{}{true},
		},
		{
			name:   "sensitive_data_diff_location_not_sensitive",
			policy: "sensitive_data",
			input: map[string]interface{}{
				"destination.ip": "10.0.0.2",
				"origin.ip":      "10.0.0.1",
				"resource.name":  "/company/acme/biz-as-usual",
				"resource.labels": map[string]string{
					"sensitivity": "public",
				},
			},
			outputs: []interface{}{},
		},
		// Timed contracts
		{
			name:   "timed_contract_valid",
			policy: "timed_contract",
			input: map[string]interface{}{
				"resource.name": "/company/warneranimstudios/hello",
				"request.time":  &tpb.Timestamp{Seconds: 1546416000},
			},
			outputs: []interface{}{},
		},
		{
			name:   "timed_contract_no_match",
			policy: "timed_contract",
			input: map[string]interface{}{
				"resource.name": "/company/othercust/some/data",
				"request.time":  &tpb.Timestamp{Seconds: 1546416000},
			},
			outputs: []interface{}{},
		},
		{
			name:   "timed_contract_invalid",
			policy: "timed_contract",
			input: map[string]interface{}{
				"resource.name": "/company/warneranimstudios/goodbye",
				"request.time":  &tpb.Timestamp{Seconds: 1646416000},
			},
			outputs: []interface{}{true},
		},
		// Restricted Destinations
		{
			name:   "restricted_destinations_valid_location",
			policy: "restricted_destinations",
			input: map[string]interface{}{
				"destination.ip":      "10.0.0.1",
				"origin.ip":           "10.0.0.1",
				"request.auth.claims": map[string]string{},
				"resource.name":       "/company/acme/secrets/doomsday-device",
				"resource.labels": map[string]string{
					"location": "us",
				},
			},
			outputs: []interface{}{},
		},
		{
			name:   "restricted_destinations_restricted_location_us_national",
			policy: "restricted_destinations",
			input: map[string]interface{}{
				"destination.ip": "10.0.0.3",
				"origin.ip":      "10.0.0.3",
				"request.auth.claims": map[string]string{
					"nationality": "us",
				},
				"resource.labels": map[string]string{},
			},
			outputs: []interface{}{true},
		},
		{
			name:   "restricted_destinations_restricted_location_ir_national",
			policy: "restricted_destinations",
			input: map[string]interface{}{
				"destination.ip": "10.0.0.3",
				"origin.ip":      "10.0.0.1",
				"request.auth.claims": map[string]string{
					"nationality": "ir",
				},
				"resource.labels": map[string]string{},
			},
			outputs: []interface{}{},
		},
		{
			name:   "restricted_destinations_valid_location_ir_label",
			policy: "restricted_destinations",
			input: map[string]interface{}{
				"destination.ip":      "10.0.0.2",
				"origin.ip":           "10.0.0.1",
				"request.auth.claims": map[string]string{},
				"resource.labels": map[string]string{
					"location": "ir",
				},
			},
			outputs: []interface{}{true},
		},
		// Required labels
		{
			name:   "required_labels_violation",
			policy: "required_labels",
			input: map[string]interface{}{
				"resource.labels": map[string]string{
					"env":    "dev",
					"ssh":    "enabled",
					"random": "bar",
				},
			},
			outputs: []interface{}{
				violation{
					Message: "missing one or more required labels",
					Details: &metadata{
						Data: []string{"verified"},
					},
				},
				violation{
					Message: "invalid values provided on one or more labels",
					Details: &metadata{
						Data: []string{"verified"},
					},
				},
			},
		},
		// Resource Types
		{
			name:   "resource_types_denied_request",
			policy: "resource_types",
			input: map[string]interface{}{
				"resource.type": "sqladmin.googleapis.com/Instance",
				"resource.name": "forbidden-my-sql-instance",
				"resource.labels": map[string]string{
					"env": "prod",
				},
			},
			outputs: []interface{}{
				violation{
					Message: "forbidden-my-sql-instance is in violation.",
					Details: &metadata{
						Resource: "forbidden-my-sql-instance",
						Mode:     "deny",
						ResourceTypes: []string{
							"sqladmin.googleapis.com/Instance",
							"compute.googleapis.com/Instance",
							"dataproc.googleapis.com/Job",
						},
					},
				},
			},
		},
		{
			name:   "resource_types_not_selected",
			policy: "resource_types",
			input: map[string]interface{}{
				"resource.type": "sqladmin.googleapis.com/Instance",
				"resource.name": "forbidden-my-sql-instance",
				"resource.labels": map[string]string{
					"env": "dev",
				},
			},
			outputs: []interface{}{},
		},
	}
)

func TestEngine(t *testing.T) {
	tr := test.NewReader("testdata")
	env, _ := cel.NewEnv(test.Decls)
	for _, tstVal := range testCases {
		tst := tstVal
		t.Run(tst.name, func(tt *testing.T) {
			opts := []EngineOption{
				Functions(test.Funcs...),
				Selectors(labelSelector),
				RangeLimit(1),
			}
			if tst.opts != nil {
				opts = append(opts, tst.opts...)
			}
			engine, err := NewEngine(opts...)
			if err != nil {
				tt.Fatal(err)
			}
			engine.AddEnv("", env)

			tmplFile := fmt.Sprintf("testdata/%s/template.yaml", tst.policy)
			tmplSrc := tr.Read(tmplFile)
			tmpl, iss := engine.CompileTemplate(tmplSrc)
			if iss.Err() != nil {
				tt.Fatal(iss.Err())
			}
			err = engine.AddTemplate(tmpl)
			if err != nil {
				tt.Fatal(err)
			}

			instFile := fmt.Sprintf("testdata/%s/instance.yaml", tst.policy)
			instSrc := tr.Read(instFile)
			inst, iss := engine.CompileInstance(instSrc)
			if iss.Err() != nil {
				tt.Fatal(iss.Err())
			}
			engine.AddInstance(inst)
			decisions, err := engine.Eval(tst.input)
			if err != nil {
				tt.Error(err)
			}
			found := false
			for _, dec := range decisions {
				for _, out := range tst.outputs {
					ntv, err := dec.Value.ConvertToNative(reflect.TypeOf(out))
					if err != nil {
						tt.Fatalf("out type: %T, err: %v", dec.Value, err)
					}
					if reflect.DeepEqual(ntv, out) {
						found = true
						break
					}
					tt.Logf("out: %v", dec.Value)
				}
				if !found {
					tt.Fatalf("Got decision %v, wanted one of %v", dec, tst.outputs)
				}
			}
			if len(decisions) != len(tst.outputs) {
				tt.Fatalf("Got decisions %v, but expected %v", decisions, tst.outputs)
			}
		})
	}
}

func BenchmarkEnforcer(b *testing.B) {
	tr := test.NewReader("testdata")
	env, _ := cel.NewEnv(test.Decls)
	for _, tstVal := range testCases {
		tst := tstVal
		opts := []EngineOption{
			Functions(test.Funcs...),
			Selectors(labelSelector),
			RangeLimit(1),
		}
		if tst.opts != nil {
			opts = append(opts, tst.opts...)
		}
		engine, err := NewEngine(opts...)
		if err != nil {
			b.Fatal(err)
		}
		engine.AddEnv("", env)
		tmplFile := fmt.Sprintf("testdata/%s/template.yaml", tst.policy)
		tmplSrc := tr.Read(tmplFile)
		tmpl, iss := engine.CompileTemplate(tmplSrc)
		if iss.Err() != nil {
			b.Fatal(iss.Err())
		}
		err = engine.AddTemplate(tmpl)
		if err != nil {
			b.Fatal(err)
		}

		instFile := fmt.Sprintf("testdata/%s/instance.yaml", tst.policy)
		instSrc := tr.Read(instFile)
		inst, iss := engine.CompileInstance(instSrc)
		if iss.Err() != nil {
			b.Fatal(iss.Err())
		}
		engine.AddInstance(inst)

		b.Run(tst.name, func(bb *testing.B) {
			for i := 0; i < bb.N; i++ {
				_, err := engine.Eval(tst.input)
				if err != nil {
					bb.Fatal(err)
				}
			}
		})
	}
}

func labelSelector(sel model.Selector, vars interpreter.Activation) bool {
	switch s := sel.(type) {
	case *model.LabelSelector:
		lbls, found := vars.ResolveName("resource.labels")
		if !found {
			return len(s.LabelValues) == 0
		}
		l := lbls.(map[string]string)
		for k, v := range s.LabelValues {
			lv, found := l[k]
			if !found || lv != v {
				return false
			}
		}
		return true
	default:
		// TODO: implement
		return false
	}
}
