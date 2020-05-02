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
	"bytes"
	"time"

	"github.com/google/cel-go/cel"

	structpb "github.com/golang/protobuf/ptypes/struct"
)

// EncodeStyle is a hint for string encoding of parsed values.
type EncodeStyle int

const (
	// BlockValueStyle is the default string encoding which preserves whitespace and newlines.
	BlockValueStyle EncodeStyle = iota

	// FlowValueStyle indicates that the string is an inline representation of complex types.
	FlowValueStyle

	// FoldedValueStyle is a multiline string with whitespace and newlines trimmed to a single
	// a whitespace. Repeated newlines are replaced with a single newline rather than a single
	// whitespace.
	FoldedValueStyle

	// LiteralStyle is a multiline string that preserves newlines, but trims all other whitespace
	// to a single character.
	LiteralStyle
)

// ParsedValue represents a top-level object representing either a template or instance value.
type ParsedValue struct {
	ID    int64
	Value *MapValue
	Info  *SourceInfo
}

// NewEmptyDynValue returns the zero-valued DynValue.
func NewEmptyDynValue() *DynValue {
	// note: 0 is not a valid parse node identifier.
	return NewDynValue(0, nil)
}

// NewDynValue returns a DynValue that corresponds to a parse node id and value.
func NewDynValue(id int64, val ValueNode) *DynValue {
	return &DynValue{ID: id, Value: val}
}

// DynValue is a dynamically typed value used to describe unstructured content.
// Whether the value has the desired type is determined by where it is used within the Instance or
// Template, and whether there are schemas which might enforce a more rigid type definition.
type DynValue struct {
	ID          int64
	Value       ValueNode
	EncodeStyle EncodeStyle
}

// ValueNode is a marker interface used to indicate which value types may populate a DynValue's
// Value field.
type ValueNode interface {
	isValueNode()

	// ModelType indicates the core CEL type represented by the value.
	ModelType() string

	// Equal indicates whether two ValueNodes are equal.
	Equal(ValueNode) bool
}

// NewMapValue returns an empty MapValue.
func NewMapValue() *MapValue {
	return &MapValue{
		Fields:   []*MapField{},
		fieldMap: map[string]*MapField{},
	}
}

// MapValue declares an object with a set of named fields whose values are dynamically typed.
type MapValue struct {
	Fields   []*MapField
	fieldMap map[string]*MapField
}

func (*MapValue) isValueNode() {}

// ModelType implements the ValueNode interface method.
func (*MapValue) ModelType() string {
	return MapType
}

// Equal returns true if the other value is a MapValue, has the same properties, and each
// property value is Equal.
func (m *MapValue) Equal(other ValueNode) bool {
	otherSv, ok := other.(*MapValue)
	if !ok || len(m.Fields) != len(otherSv.Fields) {
		return false
	}
	fields := make(map[string]*MapField)
	for _, f := range m.Fields {
		fields[f.Name] = f
	}
	for _, otherF := range otherSv.Fields {
		f, found := fields[otherF.Name]
		if !found || !f.Ref.Value.Equal(otherF.Ref.Value) {
			return false
		}
	}
	return true
}

// GetField returns a MapField by name if one exists.
func (m *MapValue) GetField(name string) (*MapField, bool) {
	field, found := m.fieldMap[name]
	return field, found
}

// AddField appends a MapField to the MapValue and indexes the field by name.
func (m *MapValue) AddField(field *MapField) {
	m.Fields = append(m.Fields, field)
	m.fieldMap[field.Name] = field
}

// NewMapField returns a MapField instance with an empty DynValue that refers to the
// specified parse node id and field name.
func NewMapField(id int64, name string) *MapField {
	return &MapField{
		ID:   id,
		Name: name,
		Ref:  NewEmptyDynValue(),
	}
}

// MapField specifies a field name and a reference to a dynamic value.
type MapField struct {
	ID   int64
	Name string
	Ref  *DynValue
}

// NewListValue returns an empty ListValue instance.
func NewListValue() *ListValue {
	return &ListValue{
		Entries: []*DynValue{},
	}
}

// ListValue contains a list of dynamically typed entries.
type ListValue struct {
	Entries []*DynValue
}

func (*ListValue) isValueNode() {}

// ModelType implements the ValueNode interface method.
func (*ListValue) ModelType() string {
	return ListType
}

// Equal returns true if the lists are of equal length and the elements are pair-wise equal.
func (lv *ListValue) Equal(other ValueNode) bool {
	otherLv, ok := other.(*ListValue)
	if !ok || len(lv.Entries) != len(otherLv.Entries) {
		return false
	}
	for i, entry := range lv.Entries {
		otherEntry := otherLv.Entries[i]
		if !entry.Value.Equal(otherEntry.Value) {
			return false
		}
	}
	return true
}

// BoolValue is a boolean value suitable for use within DynValue objects.
type BoolValue bool

func (BoolValue) isValueNode() {}

// ModelType implements the ValueNode interface method.
func (BoolValue) ModelType() string {
	return BoolType
}

// Equal implements the ValueNode interface method.
func (v BoolValue) Equal(other ValueNode) bool {
	otherV, ok := other.(BoolValue)
	return ok && v == otherV
}

// BytesValue is a []byte value suitable for use within DynValue objects.
type BytesValue []byte

func (BytesValue) isValueNode() {}

// ModelType implements the ValueNode interface method.
func (BytesValue) ModelType() string {
	return BytesType
}

// Equal returns true if the other ValueNode is a bytes instance and the byte values are equal.
func (v BytesValue) Equal(other ValueNode) bool {
	otherV, ok := other.(BytesValue)
	return ok && bytes.Equal([]byte(v), []byte(otherV))
}

// DoubleValue is a float64 value suitable for use within DynValue objects.
type DoubleValue float64

func (DoubleValue) isValueNode() {}

// ModelType implements the ValueNode interface method.
func (DoubleValue) ModelType() string {
	return DoubleType
}

// Equal implements the ValueNode interface method.
func (v DoubleValue) Equal(other ValueNode) bool {
	otherV, ok := other.(DoubleValue)
	return ok && v == otherV
}

// IntValue is an int64 value suitable for use within DynValue objects.
type IntValue int64

func (IntValue) isValueNode() {}

// ModelType implements the ValueNode interface method.
func (IntValue) ModelType() string {
	return IntType
}

// Equal implements the ValueNode interface method.
func (v IntValue) Equal(other ValueNode) bool {
	otherV, ok := other.(IntValue)
	return ok && v == otherV
}

// NullValue is a protobuf.Struct concrete null value suitable for use within DynValue objects.
type NullValue structpb.NullValue

func (NullValue) isValueNode() {}

// ModelType implements the ValueNode interface method.
func (NullValue) ModelType() string {
	return NullType
}

// Equal implements the ValueNode interface method.
func (NullValue) Equal(other ValueNode) bool {
	_, isNull := other.(NullValue)
	return isNull
}

// StringValue is a string value suitable for use within DynValue objects.
type StringValue string

func (StringValue) isValueNode() {}

// ModelType implements the ValueNode interface method.
func (StringValue) ModelType() string {
	return StringType
}

// Equal implements the ValueNode interface method.
func (v StringValue) Equal(other ValueNode) bool {
	otherV, ok := other.(StringValue)
	return ok && v == otherV
}

// PlainTextValue is a text string literal which must not be treated as an expression.
type PlainTextValue string

func (PlainTextValue) isValueNode() {}

// ModelType implements the ValueNode interface method.
func (PlainTextValue) ModelType() string {
	return PlainTextType
}

// Equal implements the ValueNode interface method.
func (v PlainTextValue) Equal(other ValueNode) bool {
	otherV, ok := other.(PlainTextValue)
	return ok && v == otherV
}

// MultilineStringValue is a multiline string value which has been parsed in a way which omits
// whitespace as well as a raw form which preserves whitespace.
type MultilineStringValue struct {
	Value string
	Raw   string
}

func (*MultilineStringValue) isValueNode() {}

// ModelType implements the ValueNode interface method.
func (*MultilineStringValue) ModelType() string {
	return StringType
}

// Equal implements the ValueNode interface method.
func (v *MultilineStringValue) Equal(other ValueNode) bool {
	otherV, ok := other.(*MultilineStringValue)
	return ok && v.Value == otherV.Value
}

// TimestampValue is a timestamp type compatible with both Open API Schema and protobuf.Timestamp.
type TimestampValue time.Time

func (TimestampValue) isValueNode() {}

// ModelType implements the ValueNode interface method.
func (TimestampValue) ModelType() string {
	return TimestampType
}

// Equal implements the ValueNode interface method.
func (v TimestampValue) Equal(other ValueNode) bool {
	otherV, ok := other.(TimestampValue)
	return ok && otherV == v
}

// UintValue is a uint64 value suitable for use within DynValue objects.
type UintValue uint64

func (UintValue) isValueNode() {}

// ModelType implements the ValueNode interface method.
func (UintValue) ModelType() string {
	return UintType
}

// Equal implements the ValueNode interface method.
func (v UintValue) Equal(other ValueNode) bool {
	otherV, ok := other.(UintValue)
	return ok && v == otherV
}

type ExprValue cel.Ast

func (*ExprValue) isValueNode() {}

func (e *ExprValue) ModelType() string {
	return ExprType
}

func (e *ExprValue) Equal(other ValueNode) bool {
	otherE, ok := other.(*ExprValue)
	ea := cel.Ast(*e)
	otherEA := cel.Ast(*otherE)
	expr, _ := cel.AstToString(&ea)
	otherExpr, _ := cel.AstToString(&otherEA)
	return ok && expr == otherExpr
}

// Null is a singleton NullValue instance.
var Null NullValue
