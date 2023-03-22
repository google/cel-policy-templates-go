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
	"time"

	"github.com/google/cel-policy-templates-go/policy/model"
	"github.com/google/cel-policy-templates-go/policy/runtime"
	"github.com/google/cel-policy-templates-go/test"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/interpreter"
)

type metadata struct {
	Template      string
	Instance      string
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
	testCases = []struct {
		name             string
		policy           string
		input            map[string]interface{}
		outputs          []interface{}
		opts             []EngineOption
		selectorsOutputs []struct {
			selector model.DecisionSelector
			outputs  []interface{}
		}
	}{
		{
			name:   "validator_with_custom_function_test",
			policy: "validator_with_custom_function",
			input: map[string]interface{}{
				"port": "22",
			},
			opts: []EngineOption{
				ValidatorProductionLimit(8),
				ValidatorTermLimit(15),
				EvaluatorTermLimit(15),
			},
			outputs: []interface{}{
				"22-60",
			},
		},
		// Binauthz
		{
			name:   "binauthz_package_violations",
			policy: "binauthz",
			input: map[string]interface{}{
				"request": map[string]interface{}{
					"packages": []interface{}{
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
			},
			outputs: []interface{}{
				violation{
					Message: "package minted-fail: disallowed build target",
				},
				violation{
					Message: "package unminted-fail: not verifiably built",
				},
			},
			opts: []EngineOption{
				EvaluatorTermLimit(8),
				EvaluatorProductionLimit(5),
			},
		},
		// Dependent ranges
		{
			name:   "dependent_ranges_behavior",
			policy: "dependent_ranges",
			input:  map[string]interface{}{},
			outputs: []interface{}{
				[]int64{2, 3, 6},
				[]int64{3, 2, 6},
			},
			opts: []EngineOption{
				RangeLimit(2),
			},
		},
		// Greeting
		{
			name:   "greeting_details",
			policy: "greeting",
			input: map[string]interface{}{
				"resource.labels": map[string]string{
					"env": "prod",
				},
			},
			outputs: []interface{}{
				"Hello",
				"You survived Y2K!",
				"Happy New Year's!",
				"Farewell",
				"Aloha",
				map[string][]int64{
					"gone": {1999},
					"next": {2038},
				},
				time.Duration(600) * time.Second,
			},
			opts: []EngineOption{
				ValidatorTermLimit(12),
				EvaluatorDecisionLimit(4),
				RuleLimit(10),
			},
		},
		// Map ranges
		{
			name:   "map_ranges_behavior",
			policy: "map_ranges",
			input:  map[string]interface{}{},
			outputs: []interface{}{
				"com.google",
			},
		},
		// Multiple ranges
		{
			name:   "multiple_ranges_behavior",
			policy: "multiple_ranges",
			input:  map[string]interface{}{},
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
			selectorsOutputs: []struct {
				selector model.DecisionSelector
				outputs  []interface{}
			}{
				{
					outputs: []interface{}{true},
				},
				{
					selector: DecisionNames("policy.deny"),
					outputs:  []interface{}{true},
				},
				{
					selector: DecisionNames("policy.report"),
					outputs:  []interface{}{},
				},
				{
					selector: UnfinalizedDecisions([]model.DecisionValue{}),
					outputs:  []interface{}{true},
				},
				{
					selector: UnfinalizedDecisions([]model.DecisionValue{
						model.NewBoolDecisionValue("policy.deny", types.True).Finalize(nil, nil),
					}),
					outputs: []interface{}{},
				},
				{
					selector: UnfinalizedDecisions([]model.DecisionValue{
						model.NewBoolDecisionValue("policy.deny", types.False),
					}),
					outputs: []interface{}{true},
				},
				{
					selector: UnfinalizedDecisions([]model.DecisionValue{
						model.NewBoolDecisionValue("policy.allow", types.True),
						model.NewBoolDecisionValue("policy.shadow", types.True),
					}),
					outputs: []interface{}{true},
				},
			},
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
				"request.time":  time.Unix(1546416000, 0).UTC(),
			},
			outputs: []interface{}{},
			opts:    []EngineOption{RuleLimit(-1)},
		},
		{
			name:   "timed_contract_no_match",
			policy: "timed_contract",
			input: map[string]interface{}{
				"resource.name": "/company/othercust/some/data",
				"request.time":  time.Unix(1546416000, 0).UTC(),
			},
			outputs: []interface{}{},
			opts:    []EngineOption{RuleLimit(-1)},
		},
		{
			name:   "timed_contract_invalid",
			policy: "timed_contract",
			input: map[string]interface{}{
				"resource.name": "/company/warneranimstudios/goodbye",
				"request.time":  time.Unix(1646416000, 0).UTC(),
			},
			outputs: []interface{}{true},
			opts:    []EngineOption{RuleLimit(-1)},
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
						Data: []string{"env"},
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
						Template: "resource_types",
						Instance: "restricted_resource_types",
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
	tr := test.NewReader("../test/testdata")
	env, _ := cel.NewEnv(test.Decls)
	for _, tstVal := range testCases {
		tst := tstVal
		t.Run(tst.name, func(tt *testing.T) {
			opts := []EngineOption{
				StandardExprEnv(env),
				Selectors(labelSelector),
				RangeLimit(1),
				ValidatorProductionLimit(5),
				ValidatorTermLimit(10),
				EvaluatorProductionLimit(3),
				EvaluatorTermLimit(6),
				RuleLimit(1),
				RuntimeTemplateOptions(
					runtime.Functions(test.Funcs...),
					runtime.NewCollectAggregator("policy.violation"),
					runtime.NewCollectAggregator("policy.report"),
					runtime.NewOrAggregator("policy.deny"),
				),
			}
			if tst.opts != nil {
				opts = append(opts, tst.opts...)
			}
			engine, err := NewEngine(opts...)
			if err != nil {
				tt.Fatal(err)
			}

			envFile := fmt.Sprintf("../test/testdata/%s/env.yaml", tst.policy)
			envSrc, found := tr.Read(envFile)
			if found {
				mdlEnv, iss := engine.CompileEnv(envSrc)
				if iss.Err() != nil {
					tt.Fatal(iss.Err())
				}
				err = engine.SetEnv(mdlEnv.Name, mdlEnv)
				if err != nil {
					tt.Fatal(err)
				}
			}

			tmplFile := fmt.Sprintf("../test/testdata/%s/template.yaml", tst.policy)
			tmplSrc, _ := tr.Read(tmplFile)
			tmpl, iss := engine.CompileTemplate(tmplSrc)
			if iss.Err() != nil {
				tt.Fatal(iss.Err())
			}
			err = engine.SetTemplate(tmpl.Metadata.Name, tmpl)
			if err != nil {
				tt.Fatal(err)
			}

			instFile := fmt.Sprintf("../test/testdata/%s/instance.yaml", tst.policy)
			instSrc, _ := tr.Read(instFile)
			inst, iss := engine.CompileInstance(instSrc)
			if iss.Err() != nil {
				tt.Fatal(iss.Err())
			}
			engine.AddInstance(inst)
			decisions, err := engine.EvalAll(tst.input)
			if err != nil {
				tt.Error(err)
			}
			for _, dec := range decisions {
				var anyEq bool
				for _, out := range tst.outputs {
					eq, err := decisionMatchesOutput(dec, out)
					if err != nil {
						tt.Fatalf("out type: %v, err: %v", dec, err)
					}
					if eq {
						anyEq = true
					}
				}
				if !anyEq {
					tt.Errorf("decision %v missing output: %v", dec, tst.outputs)
				}
			}
			if len(tst.outputs) != 0 && len(decisions) == 0 {
				tt.Errorf("got an empty decision set, expected outputs: %v", tst.outputs)
			}
			if tst.selectorsOutputs == nil {
				return
			}
			for i, selOut := range tst.selectorsOutputs {
				so := selOut
				tt.Run(fmt.Sprintf("selector[%d]", i), func(ttt *testing.T) {
					decisions, err := engine.Eval(tst.input, so.selector)
					if err != nil {
						ttt.Error(err)
					}
					for _, dec := range decisions {
						for _, out := range so.outputs {
							eq, err := decisionMatchesOutput(dec, out)
							if err != nil {
								ttt.Fatalf("out type: %v, err: %v", dec, err)
							}
							if !eq {
								ttt.Errorf("decision %v missing output: %v", dec, out)
							}
						}
					}
					if len(so.outputs) != 0 && len(decisions) == 0 {
						ttt.Errorf("got an empty decision set, expected outputs: %v", so.outputs)
					}
				})
			}
		})
	}
}

func BenchmarkEngine(b *testing.B) {
	tr := test.NewReader("../test/testdata")
	env, _ := cel.NewEnv(test.Decls)
	for _, tstVal := range testCases {
		tst := tstVal
		opts := []EngineOption{
			StandardExprEnv(env),
			Selectors(labelSelector),
			RangeLimit(1),
			RuntimeTemplateOptions(
				runtime.Functions(test.Funcs...),
				runtime.NewCollectAggregator("policy.violation"),
				runtime.NewCollectAggregator("policy.report"),
				runtime.NewOrAggregator("policy.deny"),
			),
		}
		if tst.opts != nil {
			opts = append(opts, tst.opts...)
		}
		engine, err := NewEngine(opts...)
		if err != nil {
			b.Fatal(err)
		}
		envFile := fmt.Sprintf("../test/testdata/%s/env.yaml", tst.policy)
		envSrc, found := tr.Read(envFile)
		if found {
			env, iss := engine.CompileEnv(envSrc)
			if iss.Err() != nil {
				b.Fatal(iss.Err())
			}
			err = engine.SetEnv(env.Name, env)
			if err != nil {
				b.Fatal(err)
			}
		}
		tmplFile := fmt.Sprintf("../test/testdata/%s/template.yaml", tst.policy)
		tmplSrc, _ := tr.Read(tmplFile)
		tmpl, iss := engine.CompileTemplate(tmplSrc)
		if iss.Err() != nil {
			b.Fatal(iss.Err())
		}
		err = engine.SetTemplate(tmpl.Metadata.Name, tmpl)
		if err != nil {
			b.Fatal(err)
		}

		instFile := fmt.Sprintf("../test/testdata/%s/instance.yaml", tst.policy)
		instSrc, _ := tr.Read(instFile)
		inst, iss := engine.CompileInstance(instSrc)
		if iss.Err() != nil {
			b.Fatal(iss.Err())
		}
		engine.AddInstance(inst)

		b.Run(tst.name, func(bb *testing.B) {
			for i := 0; i < bb.N; i++ {
				_, err := engine.EvalAll(tst.input)
				if err != nil {
					bb.Fatal(err)
				}
			}
		})
		if tst.selectorsOutputs != nil {
			for i, selOut := range tst.selectorsOutputs {
				so := selOut
				b.Run(fmt.Sprintf("%s/selector[%d]", tst.name, i), func(bb *testing.B) {
					for i := 0; i < bb.N; i++ {
						_, err := engine.Eval(tst.input, so.selector)
						if err != nil {
							bb.Error(err)
						}
					}
				})
			}
		}
	}
}

func decisionMatchesOutput(dec model.DecisionValue, out interface{}) (bool, error) {
	switch dv := dec.(type) {
	case *model.BoolDecisionValue:
		ntv, err := dv.Value().ConvertToNative(reflect.TypeOf(out))
		return err == nil && reflect.DeepEqual(ntv, out), nil
	case *model.ListDecisionValue:
		vals := dv.Values()
		for _, val := range vals {
			ntv, err := val.ConvertToNative(reflect.TypeOf(out))
			if err == nil && reflect.DeepEqual(ntv, out) {
				return true, nil
			}
		}
	}
	return false, nil
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
