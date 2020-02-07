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
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter/functions"

	tpb "github.com/golang/protobuf/ptypes/timestamp"

	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

type tc struct {
	name    string
	policy  string
	input   map[string]interface{}
	outputs []interface{}
	e       string
}

type metadata struct {
	Resource      string
	Mode          string
	ResourceTypes []string
}

type violation struct {
	Message  string
	Details  []string
	Metadata *metadata
}

type access struct {
	Deny  bool
	Allow bool
}

var (
	stdDecls = cel.Declarations(
		decls.NewIdent("destination.ip", decls.String, nil),
		decls.NewIdent("origin.ip", decls.String, nil),
		decls.NewIdent("request.auth.claims", decls.NewMapType(decls.String, decls.Dyn), nil),
		decls.NewIdent("request.time", decls.Timestamp, nil),
		decls.NewIdent("resource.name", decls.String, nil),
		decls.NewIdent("resource.type", decls.String, nil),
		decls.NewIdent("resource.labels", decls.NewMapType(decls.String, decls.String), nil),
		decls.NewFunction("locationCode",
			decls.NewOverload("location_code_string",
				[]*exprpb.Type{decls.String},
				decls.String,
			),
		),
	)

	stdFuncs = Functions(&functions.Overload{
		Operator: "location_code_string",
		Unary: func(ip ref.Val) ref.Val {
			switch ip.(types.String) {
			case types.String("10.0.0.1"):
				return types.String("us")
			case types.String("10.0.0.2"):
				return types.String("de")
			default:
				return types.String("ir")
			}
		},
	})

	testCases = []tc{
		// Required labels
		{
			name:   "required_label_violation",
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
					Details: []string{"verified"},
				},
				violation{
					Message: "invalid values provided on one or more labels",
					Details: []string{"verified"},
				},
			},
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
			outputs: []interface{}{
				access{
					Deny: true,
				},
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
			outputs: []interface{}{
				access{
					Deny: true,
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
			outputs: []interface{}{
				access{
					Deny: true,
				},
			},
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
			outputs: []interface{}{
				access{
					Deny: true,
				},
			},
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
			name:   "restricted_destinations_valic_location_ir_label",
			policy: "restricted_destinations",
			input: map[string]interface{}{
				"destination.ip":      "10.0.0.2",
				"origin.ip":           "10.0.0.1",
				"request.auth.claims": map[string]string{},
				"resource.labels": map[string]string{
					"location": "ir",
				},
			},
			outputs: []interface{}{
				access{
					Deny: true,
				},
			},
		},
		// Allowed Resource Types
		{
			name:   "allowed_resource_types_denied_request",
			policy: "allowed_resource_types",
			input: map[string]interface{}{
				"resource.type": "sqladmin.googleapis.com/Instance",
				"resource.name": "forbidden-my-sql-instance",
			},
			outputs: []interface{}{
				violation{
					Message: "forbidden-my-sql-instance is in violation.",
					Metadata: &metadata{
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
	}
)

func TestEnforcer(t *testing.T) {
	for _, tstVal := range testCases {
		tst := tstVal
		env, _ := cel.NewEnv(stdDecls)
		t.Run(tst.name, func(tt *testing.T) {
			enfOpts := []EngineOption{
				SourceFile(EvaluatorFile, fmt.Sprintf("examples/%s/evaluator.yaml", tst.policy)),
				SourceFile(TemplateFile, fmt.Sprintf("examples/%s/template.yaml", tst.policy)),
				SourceFile(InstanceFile, fmt.Sprintf("examples/%s/instance.yaml", tst.policy)),
				stdFuncs,
			}
			enforcer, err := NewEngine(env, enfOpts...)
			if err != nil {
				tt.Fatal(err)
			}
			decisions, err := enforcer.Evaluate(tst.input)
			if err != nil {
				t.Error(err)
			}
			found := false
			for _, dec := range decisions {
				for _, out := range tst.outputs {
					ntv, err := dec.ConvertToNative(reflect.TypeOf(out))
					if err != nil {
						tt.Fatalf("out type: %T, err: %v", dec, err)
					}
					if reflect.DeepEqual(ntv, out) {
						found = true
						break
					}
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
