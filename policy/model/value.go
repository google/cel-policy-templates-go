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
	"time"

	"github.com/google/cel-go/common/types"
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
func NewDynValue(id int64, val interface{}) *DynValue {
	return &DynValue{ID: id, Value: val}
}

// DynValue is a dynamically typed value used to describe unstructured content.
// Whether the value has the desired type is determined by where it is used within the Instance or
// Template, and whether there are schemas which might enforce a more rigid type definition.
type DynValue struct {
	ID          int64
	Value       interface{}
	EncodeStyle EncodeStyle
}

func (dv *DynValue) ModelType() string {
	switch dv.Value.(type) {
	case bool:
		return BoolType
	case []byte:
		return BytesType
	case float64:
		return DoubleType
	case int64:
		return IntType
	case string:
		return StringType
	case uint64:
		return UintType
	case types.Null:
		return NullType
	case time.Time:
		return TimestampType
	case PlainTextValue:
		return PlainTextType
	case *MultilineStringValue:
		return StringType
	case *ListValue:
		return ListType
	case *MapValue:
		return MapType
	}
	return "unknown"
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

// PlainTextValue is a text string literal which must not be treated as an expression.
type PlainTextValue string

// MultilineStringValue is a multiline string value which has been parsed in a way which omits
// whitespace as well as a raw form which preserves whitespace.
type MultilineStringValue struct {
	Value string
	Raw   string
}