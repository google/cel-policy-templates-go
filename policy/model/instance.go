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

// Package model contains abstract representations of policy template and instance config objects.
package model

func NewInstance() *Instance {
	return &Instance{
		Metadata:  &InstanceMetadata{},
		Selectors: []Selector{},
		Rules:     []Rule{},
	}
}

type Instance struct {
	APIVersion  string
	Kind        string
	Metadata    *InstanceMetadata
	Description string
	Selectors   []Selector
	Rules       []Rule
}

type InstanceMetadata struct {
	UID       string
	Name      string
	Namespace string
}

type Selector interface {
	isSelector()
}

type LabelSelector struct {
	LabelValues map[string]string
}

func (*LabelSelector) isSelector() {}

type ExpressionSelector struct {
	Label    string
	Operator string
	Values   []interface{}
}

func (*ExpressionSelector) isSelector() {}

type Rule interface {
	isRule()
}

type CustomRule DynValue

func (*CustomRule) isRule() {}
