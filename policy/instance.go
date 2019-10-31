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
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
)

type instanceModel struct {
	metadata map[string]string
	kind     string
	// properties consistent of a field and value.
	properties map[string]interface{}
}

func unmarshalInstanceModel(f *file) (*instanceModel, error) {
	inst := &instCrd{}
	err := f.unmarshalYaml(inst)
	if err != nil {
		return nil, err
	}
	return &instanceModel{
		metadata:   inst.Metadata,
		kind:       inst.Kind,
		properties: inst.Spec,
	}, nil
}

func (i *instanceModel) bind(tmpl *template) (*instance, error) {
	return &instance{
		baseVal:       &baseVal{},
		instanceModel: i,
		template:      tmpl,
	}, nil
}

func (i *instanceModel) templateName() string {
	return i.kind
}

type instance struct {
	*baseVal
	*instanceModel
	// template is the overarching type definition of the instance.
	template *template
}

func (i *instance) Contains(key ref.Val) ref.Val {
	v, found := i.Find(key)
	if types.IsUnknownOrError(v) {
		return v
	}
	if found {
		return types.True
	}
	return types.False
}

func (i *instance) Find(key ref.Val) (ref.Val, bool) {
	k, isStr := key.(types.String)
	if !isStr {
		return types.ValOrErr(key, "no such key: %v", key), true
	}
	fieldName := string(k)
	tk := i.template.root
	if tk.isObject() {
		tk, found := tk.fields[fieldName]
		if found {
			v := i.properties[fieldName]
			return tk.celValue(v), true
		}
	}
	if tk.isMap() {
		v, found := i.properties[fieldName]
		if found {
			return tk.elemType.celValue(v), true
		}
	}
	return nil, false
}

func (i *instance) Get(key ref.Val) ref.Val {
	v, found := i.Find(key)
	if found {
		return v
	}
	return types.ValOrErr(key, "no such key: %v", key)
}

func (i *instance) Type() ref.Type {
	tk := &instanceType{tType: i.template.root}
	return tk
}

func (i *instance) Value() interface{} {
	return i
}

type instanceType struct {
	tType *tmplType
}

func (it *instanceType) HasTrait(trait int) bool {
	return traits.ContainerType == trait ||
		traits.IndexerType == trait
}

func (it *instanceType) TypeName() string {
	return it.tType.TypeName()
}

type instCrd struct {
	APIVersion string                 `yaml:"apiVersion"`
	Kind       string                 `yaml:"kind"`
	Metadata   map[string]string      `yaml:"metadata"`
	Spec       map[string]interface{} `yaml:"spec"`
}
