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

	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"

	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

func newSchemaTypeProvider(kind string, schema *OpenAPISchema) *schemaTypeProvider {
	root := &schemaType{
		objectPath: kind,
		schema:     schema,
	}
	types := map[string]*schemaType{}
	buildSchemaTypes(root, types)
	return &schemaTypeProvider{
		root:  root,
		types: types,
	}
}

type schemaTypeProvider struct {
	root  *schemaType
	types map[string]*schemaType
}

type schemaType struct {
	schema     *OpenAPISchema
	objectPath string

	keyType  *schemaType
	elemType *schemaType
	fields   map[string]*schemaType
	metadata map[string]string
}

func (st *schemaType) CommonType() string {
	return st.schema.CommonType()
}

func (st *schemaType) ExprType() *exprpb.Type {
	ct := st.CommonType()
	val, found := simpleExprTypes[ct]
	if found {
		return val
	}
	if ct == "any" {
		return decls.Dyn
	}
	if ct == "list" {
		return decls.NewListType(st.elemType.ExprType())
	}
	if ct == "map" && st.schema.AdditionalProperties != nil {
		return decls.NewMapType(st.keyType.ExprType(), st.elemType.ExprType())
	}
	// This is a hack around the fact that field types are resolved relative to a type name.
	// In the absence of a proper type name for an element of an Open API Schema definition,
	// the object path used to get to the field is used. This could be addressed at a CEL API
	// level with a change to the TypeProvider to support field resolution from a type
	return decls.NewObjectType(st.objectPath)
}

func (st *schemaType) HasTrait(trait int) bool {
	return typeTraits[st.CommonType()]&trait == trait
}

func (st *schemaType) TypeName() string {
	ct := st.CommonType()
	switch ct {
	case "any":
		return st.objectPath
	case "map":
		// Hack for making sure field types can be resolved.
		if len(st.schema.Properties) > 0 {
			return st.objectPath
		}
	}
	return ct
}

func (st *schemaType) isObject() bool {
	return len(st.schema.Properties) > 0
}

func buildSchemaTypes(t *schemaType, types map[string]*schemaType) {
	t.fields = map[string]*schemaType{}
	// Build up the nested schema types in the map.
	for name, def := range t.schema.Properties {
		fieldType := &schemaType{
			schema:     def,
			objectPath: fmt.Sprintf("%s.%s", t.objectPath, name),
		}
		t.fields[name] = fieldType
		fieldCommonType := def.CommonType()
		if fieldCommonType == "map" || fieldCommonType == "list" {
			buildSchemaTypes(fieldType, types)
		}
	}
	// Additional map properties
	if t.schema.AdditionalProperties != nil {
		stringKey := NewOpenAPISchema()
		stringKey.Type = "string"
		t.keyType = &schemaType{
			schema:     stringKey,
			objectPath: fmt.Sprintf("%s.@key", t.objectPath),
		}
		t.elemType = &schemaType{
			schema:     t.schema.AdditionalProperties,
			objectPath: fmt.Sprintf("%s.@prop", t.objectPath),
		}
		fieldCommonType := t.elemType.CommonType()
		if fieldCommonType == "map" || fieldCommonType == "list" {
			buildSchemaTypes(t.elemType, types)
		}
	}
	// List element properties
	if t.schema.Items != nil {
		t.elemType = &schemaType{
			schema:     t.schema.Items,
			objectPath: fmt.Sprintf("%s.@idx", t.objectPath),
		}
		elemCommonType := t.elemType.CommonType()
		if elemCommonType == "map" || elemCommonType == "list" {
			buildSchemaTypes(t.elemType, types)
		}
	}
}

type baseVal struct {
	sType *schemaType
	value interface{}
}

func (*baseVal) ConvertToNative(typeDesc reflect.Type) (interface{}, error) {
	return nil, fmt.Errorf("unsupported native conversion to: %v", typeDesc)
}

func (*baseVal) ConvertToType(t ref.Type) ref.Val {
	return types.NewErr("unsupported type conversion to: %v", t)
}

func (*baseVal) Equal(other ref.Val) ref.Val {
	return types.NewErr("unsupported equality test between instances")
}

func (v *baseVal) Type() ref.Type {
	return v.sType
}

func (v *baseVal) Value() interface{} {
	return v.value
}

func newEmptyList() *baseList {
	schema := NewOpenAPISchema()
	schema.Type = "array"
	sType := &schemaType{
		schema: schema,
	}
	return &baseList{
		baseVal: &baseVal{
			sType: sType,
			value: []ref.Val{},
		},
		elems: []ref.Val{},
	}
}

type baseList struct {
	*baseVal
	elems []ref.Val
}

func (a *baseList) Add(other ref.Val) ref.Val {
	oArr, isArr := other.(traits.Lister)
	if !isArr {
		return types.ValOrErr(other, "unsupported operation")
	}
	szRight := len(a.elems)
	szLeft := int(oArr.Size().(types.Int))
	sz := szRight + szLeft
	combo := make([]ref.Val, sz, sz)
	for i := 0; i < szRight; i++ {
		combo[i] = a.Get(types.Int(i))
	}
	for i := 0; i < szLeft; i++ {
		combo[i+szRight] = oArr.Get(types.Int(i))
	}
	return types.NewValueList(types.DefaultTypeAdapter, combo)
}

func (a *baseList) ConvertToNative(typeDesc reflect.Type) (interface{}, error) {
	// Non-list conversion.
	if typeDesc.Kind() != reflect.Slice && typeDesc.Kind() != reflect.Array {
		return nil, fmt.Errorf("type conversion error from list to '%v'", typeDesc)
	}

	// If the list is already assignable to the desired type return it.
	if reflect.TypeOf(a).AssignableTo(typeDesc) {
		return a, nil
	}

	// List conversion.
	otherElem := typeDesc.Elem()

	// Allow the element ConvertToNative() function to determine whether conversion is possible.
	sz := len(a.elems)
	nativeList := reflect.MakeSlice(typeDesc, int(sz), int(sz))
	for i := 0; i < sz; i++ {
		elem := a.elems[i]
		nativeElemVal, err := elem.ConvertToNative(otherElem)
		if err != nil {
			return nil, err
		}
		nativeList.Index(int(i)).Set(reflect.ValueOf(nativeElemVal))
	}
	return nativeList.Interface(), nil
}

func (a *baseList) Contains(val ref.Val) ref.Val {
	if types.IsUnknownOrError(val) {
		return val
	}
	var err ref.Val
	sz := len(a.elems)
	for i := 0; i < sz; i++ {
		elem := a.elems[i]
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

func (a *baseList) Equal(other ref.Val) ref.Val {
	oArr, isArr := other.(traits.Lister)
	if !isArr {
		return types.ValOrErr(other, "unsupported operation")
	}
	sz := types.Int(len(a.elems))
	if sz != oArr.Size() {
		return types.False
	}
	for i := types.Int(0); i < sz; i++ {
		cmp := a.Get(i).Equal(oArr.Get(i))
		if cmp != types.True {
			return cmp
		}
	}
	return types.True
}

func (a *baseList) Get(idx ref.Val) ref.Val {
	iv, isInt := idx.(types.Int)
	if !isInt {
		return types.ValOrErr(idx, "unsupported index: %v", idx)
	}
	i := int(iv)
	if i < 0 || i >= len(a.elems) {
		return types.NewErr("index out of bounds: %v", idx)
	}
	return a.elems[i]
}

func (a *baseList) Iterator() traits.Iterator {
	return &baseListIterator{
		baseVal: &baseVal{},
		getter:  a.Get,
		sz:      len(a.elems),
	}
}

func (a *baseList) Size() ref.Val {
	return types.Int(len(a.elems))
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

func newEmptyObject(sType *schemaType) *baseMap {
	return &baseMap{
		baseVal: &baseVal{
			sType: sType,
			value: map[ref.Val]ref.Val{},
		},
		entries: map[ref.Val]ref.Val{},
	}
}

func newEmptyMap() *baseMap {
	schema := NewOpenAPISchema()
	schema.Type = "object"
	sType := &schemaType{
		schema: schema,
	}
	return newEmptyObject(sType)
}

type baseMap struct {
	*baseVal
	entries map[ref.Val]ref.Val
}

func (m *baseMap) Contains(key ref.Val) ref.Val {
	v, found := m.Find(key)
	if v != nil && types.IsUnknownOrError(v) {
		return v
	}
	if found {
		return types.True
	}
	return types.False
}

func (m *baseMap) Equal(other ref.Val) ref.Val {
	oMap, isMap := other.(traits.Mapper)
	if !isMap {
		return types.ValOrErr(other, "unsupported operation")
	}
	if m.Size() != oMap.Size() {
		return types.False
	}
	it := m.Iterator()
	for it.HasNext() == types.True {
		k := it.Next()
		v := m.Get(k)
		ov := oMap.Get(k)
		vEq := v.Equal(ov)
		if vEq != types.True {
			return vEq
		}
	}
	return types.True
}

func (m *baseMap) Find(key ref.Val) (ref.Val, bool) {
	v, found := m.entries[key]
	if found {
		return v, true
	}
	// if the type is actually
	if !m.sType.isObject() {
		// key and elem types are only set if there are additional properties.
		if key.Type().TypeName() != m.sType.keyType.TypeName() {
			return types.ValOrErr(key, "unsupported key: %v", key), true
		}
		return nil, false
	}
	k, isStr := key.(types.String)
	if !isStr {
		return types.ValOrErr(key, "unsupported key: %v", key), true
	}
	fType, found := m.sType.fields[string(k)]
	if !found {
		return nil, false
	}
	defaultVal, found := typeDefaults[fType.TypeName()]
	if found {
		return defaultVal, true
	}
	if fType.isObject() {
		return newEmptyObject(fType), true
	}
	return nil, false
}

func (m *baseMap) Get(key ref.Val) ref.Val {
	v, found := m.Find(key)
	if found {
		return v
	}
	return types.ValOrErr(key, "no such key: %v", key)
}

func (m *baseMap) IsSet(key ref.Val) ref.Val {
	return m.Contains(key)
}

func (m *baseMap) Iterator() traits.Iterator {
	keys := make([]ref.Val, len(m.entries))
	i := 0
	for k := range m.entries {
		keys[i] = k
		i++
	}
	return &baseMapIterator{
		baseVal: &baseVal{},
		keys:    keys,
	}
}

func (m *baseMap) Size() ref.Val {
	return types.Int(len(m.entries))
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

var (
	numericTraits = traits.AdderType |
		traits.ComparerType |
		traits.DividerType |
		traits.ModderType |
		traits.MultiplierType |
		traits.NegatorType |
		traits.SubtractorType
	bytesTraits = traits.ComparerType |
		traits.AdderType |
		traits.SizerType
	containerTraits = traits.ContainerType |
		traits.IndexerType |
		traits.IterableType |
		traits.SizerType
	typeTraits = map[string]int{
		"bool":   traits.ComparerType | traits.NegatorType,
		"double": numericTraits,
		"int":    numericTraits,
		"string": bytesTraits,
		"bytes":  bytesTraits,
		"list":   containerTraits | traits.AdderType,
		"map":    containerTraits | traits.FieldTesterType,
	}
	typeDefaults = map[string]ref.Val{
		"bool":   types.False,
		"bytes":  types.Bytes([]byte{}),
		"double": types.Double(0),
		"int":    types.Int(0),
		"string": types.String(""),
		"list":   newEmptyList(),
		"map":    newEmptyMap(),
	}
	simpleExprTypes = map[string]*exprpb.Type{
		"bool":      decls.Bool,
		"bytes":     decls.Bytes,
		"double":    decls.Double,
		"null":      decls.Null,
		"int":       decls.Int,
		"string":    decls.String,
		"timestamp": decls.Timestamp,
	}
)
