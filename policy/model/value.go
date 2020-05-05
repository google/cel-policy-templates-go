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
	"fmt"
	"reflect"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"

	tpb "github.com/golang/protobuf/ptypes/timestamp"
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

func (dv *DynValue) ConvertToNative(typeDesc reflect.Type) (interface{}, error) {
	ev := dv.ExprValue()
	if types.IsError(ev) {
		return nil, ev.(*types.Err)
	}
	return ev.ConvertToNative(typeDesc)
}

func (dv *DynValue) Equal(other ref.Val) ref.Val {
	dvType := dv.Type()
	otherType := other.Type()
	if dvType.TypeName() != otherType.TypeName() {
		return types.MaybeNoSuchOverloadErr(other)
	}
	switch v := dv.Value.(type) {
	case ref.Val:
		return v.Equal(other)
	case PlainTextValue:
		return celBool(string(v) == other.Value().(string))
	case *MultilineStringValue:
		return celBool(v.Value == other.Value().(string))
	case time.Time:
		otherTimestamp := other.Value().(*tpb.Timestamp)
		otherTime, err := ptypes.Timestamp(otherTimestamp)
		if err != nil {
			return types.NewErr(err.Error())
		}
		return celBool(v.Equal(otherTime))
	default:
		return celBool(reflect.DeepEqual(v, other.Value()))
	}
}

func (dv *DynValue) ExprValue() ref.Val {
	switch v := dv.Value.(type) {
	case ref.Val:
		return v
	case bool:
		return types.Bool(v)
	case []byte:
		return types.Bytes(v)
	case float64:
		return types.Double(v)
	case int64:
		return types.Int(v)
	case string:
		return types.String(v)
	case uint64:
		return types.Uint(v)
	case PlainTextValue:
		return types.String(string(v))
	case *MultilineStringValue:
		return types.String(v.Value)
	case time.Time:
		tbuf, err := ptypes.TimestampProto(v)
		if err != nil {
			return types.NewErr(err.Error())
		}
		return types.Timestamp{Timestamp: tbuf}
	default:
		return types.NewErr("no such expr type: %T", v)
	}
}

func (dv *DynValue) Type() ref.Type {
	switch v := dv.Value.(type) {
	case ref.Val:
		return v.Type()
	case bool:
		return types.BoolType
	case []byte:
		return types.BytesType
	case float64:
		return types.DoubleType
	case int64:
		return types.IntType
	case string, PlainTextValue, *MultilineStringValue:
		return types.StringType
	case uint64:
		return types.UintType
	case time.Time:
		return types.TimestampType
	}
	return types.ErrType
}

// PlainTextValue is a text string literal which must not be treated as an expression.
type PlainTextValue string

// MultilineStringValue is a multiline string value which has been parsed in a way which omits
// whitespace as well as a raw form which preserves whitespace.
type MultilineStringValue struct {
	Value string
	Raw   string
}

func newStructValue() *structValue {
	return &structValue{
		Fields:   []*Field{},
		fieldMap: map[string]*Field{},
	}
}

type structValue struct {
	Fields   []*Field
	fieldMap map[string]*Field
}

// AddField appends a MapField to the MapValue and indexes the field by name.
func (sv *structValue) AddField(field *Field) {
	sv.Fields = append(sv.Fields, field)
	sv.fieldMap[field.Name] = field
}

// GetField returns a MapField by name if one exists.
func (sv *structValue) GetField(name string) (*Field, bool) {
	field, found := sv.fieldMap[name]
	return field, found
}

func (sv *structValue) IsSet(key ref.Val) ref.Val {
	k, ok := key.(types.String)
	if !ok {
		return types.MaybeNoSuchOverloadErr(key)
	}
	name := string(k)
	_, found := sv.fieldMap[name]
	return celBool(found)
}

func NewObjectValue(sType *schemaType) *ObjectValue {
	return &ObjectValue{
		structValue: newStructValue(),
		objectType:  sType,
	}
}

type ObjectValue struct {
	*structValue
	objectType *schemaType
}

func (o *ObjectValue) ConvertToNative(typeDesc reflect.Type) (interface{}, error) {
	return nil, nil
}

func (o *ObjectValue) ConvertToType(t ref.Type) ref.Val {
	if t == types.TypeType {
		return types.NewObjectTypeValue(o.objectType.TypeName())
	}
	if t.TypeName() == o.objectType.TypeName() {
		return o
	}
	return types.NewErr("type conversion error from '%s' to '%s'", o.Type(), t)
}

func (o *ObjectValue) Equal(other ref.Val) ref.Val {
	if o.objectType.TypeName() != other.Type().TypeName() {
		return types.NoSuchOverloadErr()
	}
	o2 := other.(traits.Indexer)
	for name, field := range o.fieldMap {
		k := types.String(name)
		ov := o2.Get(k)
		v := field.Ref.ExprValue()
		vEq := v.Equal(ov)
		if vEq != types.True {
			return vEq
		}
	}
	return types.True
}

func (o *ObjectValue) Get(name ref.Val) ref.Val {
	n, ok := name.(types.String)
	if !ok {
		return types.MaybeNoSuchOverloadErr(n)
	}
	nameStr := string(n)
	field, found := o.fieldMap[nameStr]
	if found {
		return field.Ref.ExprValue()
	}
	fieldType, found := o.objectType.fields[nameStr]
	if !found {
		return types.NewErr("no such field: %s", nameStr)
	}
	if fieldType.isObject() {
		return NewObjectValue(fieldType)
	}
	fieldDefault, found := typeDefaults[fieldType.TypeName()]
	if found {
		return fieldDefault
	}
	return types.NewErr("no default for object path: %s", fieldType.objectPath)
}

func (o *ObjectValue) Type() ref.Type {
	return o.objectType
}

func (o *ObjectValue) Value() interface{} {
	return o
}

// NewMapValue returns an empty MapValue.
func NewMapValue() *MapValue {
	return &MapValue{
		structValue: newStructValue(),
	}
}

// MapValue declares an object with a set of named fields whose values are dynamically typed.
type MapValue struct {
	*structValue
}

func (m *MapValue) Contains(key ref.Val) ref.Val {
	v, found := m.Find(key)
	if v != nil && types.IsUnknownOrError(v) {
		return v
	}
	return celBool(found)
}

func (m *MapValue) ConvertToNative(typeDesc reflect.Type) (interface{}, error) {
	return nil, nil
}

func (m *MapValue) ConvertToType(t ref.Type) ref.Val {
	switch t {
	case types.MapType:
		return m
	case types.TypeType:
		return types.MapType
	}
	return types.NewErr("type conversion error from '%s' to '%s'", m.Type(), t)
}

func (m *MapValue) Equal(other ref.Val) ref.Val {
	oMap, isMap := other.(traits.Mapper)
	if !isMap {
		return types.MaybeNoSuchOverloadErr(other)
	}
	if m.Size() != oMap.Size() {
		return types.False
	}
	for name, field := range m.fieldMap {
		k := types.String(name)
		ov, found := oMap.Find(k)
		if !found {
			return types.False
		}
		v := field.Ref.ExprValue()
		vEq := v.Equal(ov)
		if vEq != types.True {
			return vEq
		}
	}
	return types.True
}

func (m *MapValue) Find(name ref.Val) (ref.Val, bool) {
	// Currently only maps with string keys are supported as this is best aligned with JSON,
	// and also much simpler to support.
	n, ok := name.(types.String)
	if !ok {
		return types.MaybeNoSuchOverloadErr(n), true
	}
	nameStr := string(n)
	field, found := m.fieldMap[nameStr]
	if found {
		return field.Ref.ExprValue(), true
	}
	return nil, false
}

func (m *MapValue) Get(key ref.Val) ref.Val {
	v, found := m.Find(key)
	if found {
		return v
	}
	return types.ValOrErr(key, "no such key: %v", key)
}

func (m *MapValue) Iterator() traits.Iterator {
	keys := make([]ref.Val, len(m.fieldMap))
	i := 0
	for k := range m.fieldMap {
		keys[i] = types.String(k)
		i++
	}
	return &baseMapIterator{
		baseVal: &baseVal{},
		keys:    keys,
	}
}

func (m *MapValue) Size() ref.Val {
	return types.Int(len(m.Fields))
}

func (m *MapValue) Type() ref.Type {
	return types.MapType
}

func (m *MapValue) Value() interface{} {
	return m
}

type baseMapIterator struct {
	*baseVal
	keys []ref.Val
	idx  int
}

func (it *baseMapIterator) HasNext() ref.Val {
	if it.idx < len(it.keys) {
		return types.True
	}
	return types.False
}

func (it *baseMapIterator) Next() ref.Val {
	key := it.keys[it.idx]
	it.idx++
	return key
}

func (it *baseMapIterator) Type() ref.Type {
	return types.IteratorType
}

// NewField returns a MapField instance with an empty DynValue that refers to the
// specified parse node id and field name.
func NewField(id int64, name string) *Field {
	return &Field{
		ID:   id,
		Name: name,
		Ref:  NewEmptyDynValue(),
	}
}

// Field specifies a field name and a reference to a dynamic value.
type Field struct {
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

func (lv *ListValue) Add(other ref.Val) ref.Val {
	oArr, isArr := other.(traits.Lister)
	if !isArr {
		return types.ValOrErr(other, "unsupported operation")
	}
	szRight := len(lv.Entries)
	szLeft := int(oArr.Size().(types.Int))
	sz := szRight + szLeft
	combo := make([]ref.Val, sz)
	for i := 0; i < szRight; i++ {
		combo[i] = lv.Entries[i].ExprValue()
	}
	for i := 0; i < szLeft; i++ {
		combo[i+szRight] = oArr.Get(types.Int(i))
	}
	return types.NewValueList(types.DefaultTypeAdapter, combo)
}

func (lv *ListValue) Contains(val ref.Val) ref.Val {
	if types.IsUnknownOrError(val) {
		return val
	}
	var err ref.Val
	sz := len(lv.Entries)
	for i := 0; i < sz; i++ {
		elem := lv.Entries[i]
		cmp := elem.Equal(val)
		b, ok := cmp.(types.Bool)
		if !ok && err == nil {
			err = types.ValOrErr(cmp, "no such overload")
		}
		if b == types.True {
			return types.True
		}
	}
	if err != nil {
		return err
	}
	return types.False
}

func (lv *ListValue) ConvertToNative(typeDesc reflect.Type) (interface{}, error) {
	// Non-list conversion.
	if typeDesc.Kind() != reflect.Slice && typeDesc.Kind() != reflect.Array {
		return nil, fmt.Errorf("type conversion error from list to '%v'", typeDesc)
	}

	// If the list is already assignable to the desired type return it.
	if reflect.TypeOf(lv).AssignableTo(typeDesc) {
		return lv, nil
	}

	// List conversion.
	otherElem := typeDesc.Elem()

	// Allow the element ConvertToNative() function to determine whether conversion is possible.
	sz := len(lv.Entries)
	nativeList := reflect.MakeSlice(typeDesc, int(sz), int(sz))
	for i := 0; i < sz; i++ {
		elem := lv.Entries[i]
		nativeElemVal, err := elem.ConvertToNative(otherElem)
		if err != nil {
			return nil, err
		}
		nativeList.Index(int(i)).Set(reflect.ValueOf(nativeElemVal))
	}
	return nativeList.Interface(), nil
}

func (lv *ListValue) ConvertToType(t ref.Type) ref.Val {
	switch t {
	case types.ListType:
		return lv
	case types.TypeType:
		return types.ListType
	}
	return types.NewErr("type conversion error from '%s' to '%s'", ListType, t)
}

func (lv *ListValue) Equal(other ref.Val) ref.Val {
	oArr, isArr := other.(traits.Lister)
	if !isArr {
		return types.ValOrErr(other, "unsupported operation")
	}
	sz := types.Int(len(lv.Entries))
	if sz != oArr.Size() {
		return types.False
	}
	for i := types.Int(0); i < sz; i++ {
		cmp := lv.Get(i).Equal(oArr.Get(i))
		if cmp != types.True {
			return cmp
		}
	}
	return types.True
}

func (lv *ListValue) Get(idx ref.Val) ref.Val {
	iv, isInt := idx.(types.Int)
	if !isInt {
		return types.ValOrErr(idx, "unsupported index: %v", idx)
	}
	i := int(iv)
	if i < 0 || i >= len(lv.Entries) {
		return types.NewErr("index out of bounds: %v", idx)
	}
	return lv.Entries[i].ExprValue()
}

func (lv *ListValue) Iterator() traits.Iterator {
	return &baseListIterator{
		getter: lv.Get,
		sz:     len(lv.Entries),
	}
}

func (lv *ListValue) Size() ref.Val {
	return types.Int(len(lv.Entries))
}

func (lv *ListValue) Type() ref.Type {
	return types.ListType
}

func (lv *ListValue) Value() interface{} {
	return lv
}

type baseVal struct{}

func (*baseVal) ConvertToNative(typeDesc reflect.Type) (interface{}, error) {
	return nil, fmt.Errorf("unsupported native conversion to: %v", typeDesc)
}

func (*baseVal) ConvertToType(t ref.Type) ref.Val {
	return types.NewErr("unsupported type conversion to: %v", t)
}

func (*baseVal) Equal(other ref.Val) ref.Val {
	return types.NewErr("unsupported equality test between instances")
}

func (v *baseVal) Value() interface{} {
	return nil
}

type baseListIterator struct {
	*baseVal
	getter func(idx ref.Val) ref.Val
	sz     int
	idx    int
}

func (it *baseListIterator) HasNext() ref.Val {
	if it.idx < it.sz {
		return types.True
	}
	return types.False
}

func (it *baseListIterator) Next() ref.Val {
	v := it.getter(types.Int(it.idx))
	it.idx++
	return v
}

func (it *baseListIterator) Type() ref.Type {
	return types.IteratorType
}

func celBool(pred bool) ref.Val {
	if pred {
		return types.True
	}
	return types.False
}
