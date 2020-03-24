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
	"reflect"
	"testing"

	"github.com/google/cel-policy-templates-go/policy/config"
)

func TestBuilders_ModelStructValue(t *testing.T) {
	sv := &config.StructValue{Fields: []*config.StructField{}}
	sb := &structBuilder{
		baseBuilder: &baseBuilder{typeName: "struct"},
		structVal:   sv,
	}

	// Simulate setting a role binding on an IAM grant policy
	sb.id(1)
	r, _ := sb.prop(2, "role")
	r.assign("role/storage.bucket.admin")
	r.id(3)
	m, _ := sb.prop(4, "members")
	m.id(5)
	m0, _ := m.propAt(0)
	m0.id(6)
	m0.assign("user:wiley@acme.co")

	want := &config.StructValue{
		Fields: []*config.StructField{
			{
				ID:   2,
				Name: "role",
				Ref: &config.DynValue{
					ID:    3,
					Value: config.StringValue("role/storage.bucket.admin"),
				},
			},
			{
				ID:   4,
				Name: "members",
				Ref: &config.DynValue{
					ID: 5,
					Value: &config.ListValue{
						Entries: []*config.DynValue{
							{
								ID:    6,
								Value: config.StringValue("user:wiley@acme.co"),
							},
						},
					},
				},
			},
		},
	}
	if !reflect.DeepEqual(sv, want) {
		t.Errorf("got %v, wanted %v", sv, want)
	}
}
