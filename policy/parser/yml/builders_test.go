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
	sv := model.NewMapValue()
	sb := &mapBuilder{
		baseBuilder: &baseBuilder{declType: model.MapType},
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

	role := model.NewField(2, "role")
	role.Ref, _ = model.NewDynValue(3, "role/storage.bucket.admin")

	members := model.NewField(4, "members")
	memberList := model.NewListValue()
	elem, _ := model.NewDynValue(6, "user:wiley@acme.co")
	memberList.Append(elem)
	members.Ref, _ = model.NewDynValue(5, memberList)

	want := model.NewMapValue()
	want.AddField(role)
	want.AddField(members)
	if !reflect.DeepEqual(sv.Fields, want.Fields) {
		t.Errorf("got %v, wanted %v", sv.Fields, want.Fields)
	}
}
