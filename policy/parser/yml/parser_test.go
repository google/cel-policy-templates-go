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

	"github.com/google/cel-policy-templates-go/policy/model"
)

func TestParse_Instance(t *testing.T) {
	tests := []struct {
		ID  string
		In  string
		Out string
	}{
		{
			ID:  "bad_instance_prop",
			In:  `kinds: GrantTemplate`,
			Out: `1~2~kinds: 3~"GrantTemplate"`,
		},
		{
			ID: "multiline_string",
			In: `apiVersion: policy.acme.com/v1
kind: MultilineTemplate
metadata:
  name: multiline
rules:
  - greeting: >
      hello world!
      how are you?
    farewell: >
      goodnight "moon"!`,
			Out: `1~2~apiVersion: 3~"policy.acme.com/v1"
4~kind: 5~"MultilineTemplate"
6~metadata:7~
	8~name: 9~"multiline"
10~rules:11~
	- 12~13~greeting: 14~"hello world! how are you?\n"
		15~farewell: 16~"goodnight \"moon\"!"`,
		},
		{
			ID: "bad_selector",
			In: `selector:
  matchLabels:
    - first
  matchExpression:`,
			Out: `1~2~selector:3~
	4~matchLabels:5~
		- 6~"first"
	7~matchExpression: 8~null`,
		},
		{
			ID: "bad_match_expressions",
			In: `selector:
  matchExpressions:
    - {key: 1, operator: true, values: none}
    - {keys: bad, values: []}`,
			Out: `1~2~selector:3~
			4~matchExpressions:5~
				- 6~{7~key: 8~1, 9~operator: 10~true, 11~values: 12~"none"}
				- 13~{14~keys: 15~"bad", 16~values: 17~[]}`,
		},
		{
			ID:  "bad_rules_type",
			In:  `rules: none`,
			Out: `1~2~rules: 3~"none"`,
		},
		{
			ID:  "missing_required_fields",
			In:  `kind: GrantTemplate`,
			Out: `1~2~kind: 3~"GrantTemplate"`,
		},
		{
			ID: "invalid_argument_type",
			In: `apiVersion: 1
kind: GrantTemplate
metadata:
  name: InvalidArgType
  namespace: true`,
			Out: ` 1~2~apiVersion: 3~1
4~kind: 5~"GrantTemplate"
6~metadata:7~
	8~name: 9~"InvalidArgType"
	10~namespace: 11~true`,
		},
		{
			ID: "invalid_enum_value",
			In: `apiVersion: policy.acme.co/v1
kind: GrantTemplate
metadata:
  name: InvalidEnumValue
selector:
  matchExpressions:
    - {key: "Test", operator: "NotExists"}`,
			Out: `1~2~apiVersion: 3~"policy.acme.co/v1"
			4~kind: 5~"GrantTemplate"
			6~metadata:7~
				8~name: 9~"InvalidEnumValue"
			10~selector:11~
				12~matchExpressions:13~
					- 14~{15~key: 16~"Test", 17~operator: 18~"NotExists"}`,
		},
		{
			ID: "comments",
			In: `# instance comment

# version header
# version multi-line
apiVersion: policy.acme.co/v1 # version inline
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
apiVersion: 3~"policy.acme.co/v1" # version inline
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
			In: `apiVersion: policy.acme.co/v1
kind: AdmissionTemplate
metadata:
  name: AllTheTypes
rules:
  - value: true
  - value: 1.2
  - value: "1000"
  - value: null`,
			Out: `1~2~apiVersion: 3~"policy.acme.co/v1"
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
			In: `apiVersion: policy.acme.co/v1
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
			Out: `1~2~apiVersion: 3~"policy.acme.co/v1"
4~kind: 5~"GrantTemplate"
6~metadata:7~
	8~name: 9~"AdminAccess"
	10~namespace: 11~"organizations/123"
12~description: 13~"This template grants!"
14~selector:15~
	16~matchLabels:17~
		18~env: 19~"prod"
		20~reason: 21~"break-glass"
	22~matchExpressions:23~
		- 24~{25~key: 26~"method", 27~operator: 28~"In", 29~values: 30~[31~"hello", 32~"world"]}
		- 33~{34~key: 35~"service", 36~operator: 37~"NotIn", 38~values: 39~[40~"debug-service"]}
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
			in := strings.ReplaceAll(tc.In, "\t", "  ")
			src := model.StringSource(in, "instance")
			inst, errs := Parse(src)
			dbgErr := errs.ToDisplayString()
			if dbgErr != "" {
				tt.Fatal(dbgErr)
			}
			if tc.Out != "" {
				dbg := Encode(inst, RenderDebugIDs)
				if !cmp(tc.Out, dbg) {
					tt.Errorf("got:\n%s\nwanted:\n%s\n", dbg, tc.Out)
				}
			}
		})
	}
}

func TestParse_Template(t *testing.T) {
	tests := []struct {
		ID  string
		In  string
		Out string
	}{
		{
			ID: "bad_props",
			In: `kinds: PolicyTemplate
validator:
	term: bad
	productions:
	  - matches: b
evaluator:
	env: default
	productions:
		- matches: a
		- match: b
			decisions:
			  - outputs: b`,
			Out: `1~2~kinds: 3~"PolicyTemplate"
4~validator:5~
	6~term: 7~"bad"
	8~productions:9~
		- 10~11~matches: 12~"b"
13~evaluator:14~
	15~env: 16~"default"
	17~productions:18~
		- 19~20~matches: 21~"a"
		- 22~23~match: 24~"b"
			25~decisions:26~
				- 27~28~outputs: 29~"b"`,
		},
		{
			ID: "evaluator_decisions",
			In: `evaluator:
	terms:
	  second: first
	productions:
		- match: a
			decision: first
			decisionRef: second
			output: a
		- match: b
			decisions:
				- decision: first
					output: b
				- decisionRef: second
				  output: c`,
			Out: `1~2~evaluator:3~
4~terms:5~
	6~second: 7~"first"
8~productions:9~
	- 10~11~match: 12~"a"
		13~decision: 14~"first"
		15~decisionRef: 16~"second"
		17~output: 18~"a"
	- 19~20~match: 21~"b"
		22~decisions:23~
			- 24~25~decision: 26~"first"
				27~output: 28~"b"
			- 29~30~decisionRef: 31~"second"
				32~output: 33~"c"`,
		},
		{
			ID: "list_with_complex_struct_comments",
			In: `schema:
  type: array
  items:
	  type: object
	  properties:
		  - obj: # comment
					nested: value
				desc: "hello"
		  - obj:
		      # comment
		      nested: value`,
			Out: `1~2~schema:3~
4~type: 5~"array"
6~items:7~
	8~type: 9~"object"
	10~properties:11~
		- 12~13~obj: # comment14~
				15~nested: 16~"value"
			17~desc: 18~"hello"
		- 19~20~obj:21~
				22~# comment
				nested: 23~"value"`,
		},
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
  environment: default
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
	environment: default
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
			Out: `1~2~apiVersion: 3~"policy.acme.co/v1"
4~kind: 5~"PolicyTemplate"
6~metadata:7~
	8~name: 9~"MultilineTemplate"
10~description: 11~"Policy for configuring greetings and farewells.\n"
12~schema:13~
	14~type: 15~"object"
	16~properties:17~
		18~greeting:19~
			20~type: 21~"string"
		22~farewell:23~
			24~type: 25~"string"
26~validator:27~
	28~environment: 29~"default"
	30~terms:31~
		32~hi: 33~"rule.greeting"
		34~bye: 35~"rule.farewell"
		36~uint: 37~9223372036854775808
	38~productions:39~
		- 40~41~match: 42~"hi == '' && bye == ''"
			43~message: 44~"at least one property must be set on the rule."
		- 45~46~match: 47~"hi.startsWith(\"Goodbye\")"
			48~message: 49~"greeting starts with a farewell word"
			50~details: 51~"hi"
52~evaluator:53~
	54~environment: 55~"default"
	56~terms:57~
		58~hi: 59~"rule.greeting"
		60~bye: 61~"rule.farewell"
	62~productions:63~
		- 64~65~match: 66~"hi != '' && bye == ''"
			67~decision: 68~"policy.acme.welcome"
			69~output: 70~"hi"
		- 71~72~match: 73~"bye != '' && hi == ''"
			74~decision: 75~"policy.acme.depart"
			76~output: 77~"bye"
		- 78~79~match: 80~"hi != '' && bye != ''"
			81~decisions:82~
				- 83~84~decision: 85~"policy.acme.welcome"
					86~output: 87~"hi"
				- 88~89~decision: 90~"policy.acme.depart"
					91~output: 92~"bye"`,
		},
	}

	for _, tst := range tests {
		tc := tst
		t.Run(tc.ID, func(tt *testing.T) {
			in := strings.ReplaceAll(tc.In, "\t", "  ")
			src := model.StringSource(in, "template")
			tmpl, errs := Parse(src)
			dbgErr := errs.ToDisplayString()
			if dbgErr != "" {
				tt.Fatal(dbgErr)
			}
			if tc.Out != "" {
				dbg := Encode(tmpl, RenderDebugIDs)
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
