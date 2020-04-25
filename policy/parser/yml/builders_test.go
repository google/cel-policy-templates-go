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

	"github.com/google/cel-policy-templates-go/policy/model"
)

func TestBuilders_ModelMapValue(t *testing.T) {
	sv := &model.MapValue{Fields: []*model.MapField{}}
	sb := &mapBuilder{
		baseBuilder: &baseBuilder{typeName: model.MapType},
		mv:          sv,
	}

	// Simulate setting a role binding on an IAM grant policy
	sb.id(1)
	r, _ := sb.field(2, "role")
	r.assign("role/storage.bucket.admin")
	r.id(3)
	m, _ := sb.field(4, "members")
	m.id(5)
	m.initList()
	m0, _ := m.entry(0)
	m0.id(6)
	m0.assign("user:wiley@acme.co")

	want := &model.MapValue{
		Fields: []*model.MapField{
			{
				ID:   2,
				Name: "role",
				Ref: &model.DynValue{
					ID:    3,
					Value: model.StringValue("role/storage.bucket.admin"),
				},
			},
			{
				ID:   4,
				Name: "members",
				Ref: &model.DynValue{
					ID: 5,
					Value: &model.ListValue{
						Entries: []*model.DynValue{
							{
								ID:    6,
								Value: model.StringValue("user:wiley@acme.co"),
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
