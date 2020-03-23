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

package model

import (
	structpb "github.com/golang/protobuf/ptypes/struct"
)

var Null NullValue

type Instance struct {
	ID          int64
	Version     *StructField
	Kind        *StructField
	Metadata    *StructField
	Description *StructField
	Selector    *Selector
	Rules       *StructField
	SourceInfo  *SourceInfo
}

type Selector struct {
	ID               int64
	MatchLabels      *MatchLabels
	MatchExpressions *MatchExpressions
}

type MatchLabels struct {
	ID       int64
	Matchers []*LabelMatcher
}

type LabelMatcher struct {
	Key   *DynValue
	Value *DynValue
}

type MatchExpressions struct {
	ID       int64
	Matchers []*ExprMatcher
}

type ExprMatcher struct {
	Key      *DynValue
	Operator *DynValue
	Values   *DynValue
}

type DynValue struct {
	ID    int64
	Value ValueNode
}

type StructValue struct {
	Fields []*StructField
}

func (*StructValue) isValueNode() {}

type StructField struct {
	ID   int64
	Name string
	Ref  *DynValue
}

type ListValue struct {
	Entries []*DynValue
}

func (*ListValue) isValueNode() {}

type ValueNode interface {
	isValueNode()
}

type BoolValue bool

func (BoolValue) isValueNode() {}

type BytesValue []byte

func (BytesValue) isValueNode() {}

type DoubleValue float64

func (DoubleValue) isValueNode() {}

type IntValue int64

func (IntValue) isValueNode() {}

type NullValue structpb.NullValue

func (NullValue) isValueNode() {}

type StringValue string

func (StringValue) isValueNode() {}

type UintValue uint64

func (UintValue) isValueNode() {}
