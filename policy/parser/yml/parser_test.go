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
	"fmt"
	"testing"

	"github.com/google/cel-policy-templates-go/policy/test"
)

func TestParse(t *testing.T) {
	tr := test.NewReader("../../testdata")
	tests, err := tr.ReadCases("parse")
	if err != nil {
		t.Fatal(err)
	}
	for _, tst := range tests {
		tc := tst
		t.Run(tc.ID, func(tt *testing.T) {
			tmpl, iss := Parse(tc.In)
			if iss.Err() != nil {
				tt.Fatal(iss.Err())
			}
			if tc.Out != "" {
				dbg := Encode(tmpl, RenderDebugIDs)
				if tc.Out != dbg {
					fmt.Println(dbg)
					tt.Errorf("got:\n%s\nwanted:\n%s\n", dbg, tc.Out)
				}
			}
		})
	}
}
