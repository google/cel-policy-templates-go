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

package yml

import (
	"strings"
	"testing"

	"github.com/google/cel-policy-templates-go/policy/config"
)

func TestDecoder(t *testing.T) {
	tests := []struct {
		ID  string
		In  string
		Out string
		Err string
	}{
		{
			ID: "bad_instance_field",
			In: `kinds: GrantTemplate`,
			Err: `ERROR: instance:1:1: no such property: type=instance, property=kinds
			| kinds: GrantTemplate
			| ^`,
		},
		{
			ID: "bad_selector",
			In: `selector:
  matchLabels:
    - first
  matchExpression:`,
			Err: `ERROR: instance:3:5: type not assignable to target: target=matchLabels, type=list
			|     - first
			| ....^
		   ERROR: instance:4:3: no such property: type=selector, property=matchExpression
			|   matchExpression:
			| ..^`,
		},
		{
			ID: "bad_match_expressions",
			In: `selector:
  matchExpressions:
    - {key: 1, operator: true, values: none}
    - {keys: bad, values: []}`,
			Err: `ERROR: instance:3:40: type not assignable to target: target=list, type=string
			|     - {key: 1, operator: true, values: none}
			| .......................................^
		   ERROR: instance:4:8: no such property: type=exprMatcher, property=keys
			|     - {keys: bad, values: []}
			| .......^`,
		},
		{
			ID: "bad_rules_type",
			In: `rules: none`,
			Err: `ERROR: instance:1:8: type not assignable to target: target=list, type=string
			| rules: none
			| .......^`,
		},
		{
			ID:  "missing_required_fields",
			In:  `kind: GrantTemplate`,
			Out: `1~2~kind: 3~"GrantTemplate"`,
		},
		{
			ID: "invalid_argument_type",
			In: `version: 1
kind: GrantTemplate
metadata:
  name: InvalidArgType
  namespace: true`,
			Out: ` 1~2~version: 3~1
4~kind: 5~"GrantTemplate"
6~metadata:7~
	8~name: 9~"InvalidArgType"
	10~namespace: 11~true`,
		},
		{
			ID: "invalid_enum_value",
			In: `version: policy.acme.co/v1
kind: GrantTemplate
metadata:
  name: InvalidEnumValue
selector:
  matchExpressions:
    - {key: "Test", operator: "NotExists"}`,
			Out: `1~2~version: 3~"policy.acme.co/v1"
4~kind: 5~"GrantTemplate"
6~metadata:7~
	8~name: 9~"InvalidEnumValue"
10~selector:
	12~matchExpressions:
	- {key: 16~"Test", operator: 18~"NotExists"}`,
		},
		{
			ID: "comments",
			In: `# instance comment

# version header
# version multi-line
version: policy.acme.co/v1 # version inline
# kind header


kind: CommentsTemplate  # kind inline
# kind footer

# metadata header
metadata: # metadata inline
  # name header
  name: CommentPolicy # name inline
  # name footer
  # name footer multi-line

  # ns header
  namespace: ns # ns inline
  # ns footer
# metadata footer

# instance footer`,
			Out: `1~# instance comment

2~# version header
# version multi-line
version: 3~"policy.acme.co/v1" # version inline
# kind header

4~kind: 5~"CommentsTemplate" # kind inline
# kind footer

6~# metadata header
metadata: # metadata inline7~
  8~# name header
  name: 9~"CommentPolicy" # name inline
  # name footer
  # name footer multi-line

  10~# ns header
  namespace: 11~"ns" # ns inline
  # ns footer

# metadata footer

# instance footer`,
		},
		{
			ID: "primitive_types",
			In: `version: policy.acme.co/v1
kind: AdmissionTemplate
metadata:
  name: AllTheTypes
rules:
  - value: true
  - value: 1.2
  - value: "1000"
  - value: null`,
			Out: `1~2~version: 3~"policy.acme.co/v1"
4~kind: 5~"AdmissionTemplate"
6~metadata:7~
	8~name: 9~"AllTheTypes"
10~rules:11~
	- 12~13~value: 14~true
	- 15~16~value: 17~1.2
	- 18~19~value: 20~"1000"
	- 21~22~value: 23~null`,
		},
		{
			ID: "canonical",
			In: `version: policy.acme.co/v1
kind: GrantTemplate
metadata:
  name: AdminAccess
  namespace: organizations/123
description: "This template grants!"
selector:
  matchLabels:
    env: prod
    reason: break-glass
  matchExpressions:
    - {key: "method", operator: "In", values: ["hello", "world"]}
    - {key: "service", operator: "NotIn", values: ["debug-service"]}
rules:
  - role: role/storage.bucket.admin
    members:
      - "group:admins@acme.co"
      - "user:ceo@acme.co"
      - nested:
          key: value
          num: 123
    condition:
      expression: request.time < now
  - role: role/storage.bucket.reader
    members:
      - "group:viewers@acme.co"
      - "user:ceo@acme.co"`,
			Out: `1~2~version: 3~"policy.acme.co/v1"
4~kind: 5~"GrantTemplate"
6~metadata:7~
  8~name: 9~"AdminAccess"
  10~namespace: 11~"organizations/123"
12~description: 13~"This template grants!"
14~selector:
  16~matchLabels:
    18~env: 19~"prod"
    20~reason: 21~"break-glass"
  22~matchExpressions:
    - {key: 26~"method", operator: 28~"In", values: [31~"hello", 32~"world"]}
    - {key: 35~"service", operator: 37~"NotIn", values: [40~"debug-service"]}
41~rules:42~
  - 43~44~role: 45~"role/storage.bucket.admin"
    46~members:47~
      - 48~"group:admins@acme.co"
      - 49~"user:ceo@acme.co"
      - 50~51~nested:52~
          53~key: 54~"value"
          55~num: 56~123
    57~condition:58~
      59~expression: 60~"request.time < now"
  - 61~62~role: 63~"role/storage.bucket.reader"
    64~members:65~
      - 66~"group:viewers@acme.co"
      - 67~"user:ceo@acme.co"`,
		},
	}

	for _, tst := range tests {
		tc := tst
		t.Run(tc.ID, func(tt *testing.T) {
			src := config.StringSource(tc.In, "instance")
			inst, errs := DecodeInstance(src)
			dbgErr := errs.ToDisplayString()
			if !cmp(tc.Err, dbgErr) {
				tt.Errorf("got:\n%s\nwanted:\n%s\n", dbgErr, tc.Err)
			}
			if tc.Out != "" {
				dbg := EncodeInstance(inst, RenderDebugIDs)
				if !cmp(tc.Out, dbg) {
					tt.Errorf("got:\n%s\nwanted:\n%s\n", dbg, tc.Out)
				}
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
