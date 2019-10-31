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
	"encoding/base64"
	"fmt"
	"reflect"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
)

type baseVal struct {
	tType *tmplType
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
	return v.tType
}

func (v *baseVal) Value() interface{} {
	return v.value
}

type baseArray struct {
	*baseVal
	lister
}

type lister interface {
	get(idx int) interface{}
	size() int
}

func (a *baseArray) Add(other ref.Val) ref.Val {
	oArr, isArr := other.(traits.Lister)
	if !isArr {
		return types.ValOrErr(other, "unsupported operation")
	}
	szRight := a.size()
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

func (a *baseArray) ConvertToNative(typeDesc reflect.Type) (interface{}, error) {
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
	elemCount := a.Size().(types.Int)
	nativeList := reflect.MakeSlice(typeDesc, int(elemCount), int(elemCount))
	for i := types.Int(0); i < elemCount; i++ {
		elem := a.Get(types.Int(i))
		nativeElemVal, err := elem.ConvertToNative(otherElem)
		if err != nil {
			return nil, err
		}
		nativeList.Index(int(i)).Set(reflect.ValueOf(nativeElemVal))
	}
	return nativeList.Interface(), nil
}

func (a *baseArray) Contains(val ref.Val) ref.Val {
	if types.IsUnknownOrError(val) {
		return val
	}
	var err ref.Val
	sz := a.Size().(types.Int)
	for i := types.Int(0); i < sz; i++ {
		elem := a.Get(i)
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

func (a *baseArray) Equal(other ref.Val) ref.Val {
	oArr, isArr := other.(traits.Lister)
	if !isArr {
		return types.ValOrErr(other, "unsupported operation")
	}
	sz := a.Size().(types.Int)
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

func (a *baseArray) Get(idx ref.Val) ref.Val {
	iv, isInt := idx.(types.Int)
	if !isInt {
		return types.ValOrErr(idx, "unsupported index: %v", idx)
	}
	i := int(iv)
	if i < 0 || i >= a.size() {
		return types.NewErr("index out of bounds: %v", idx)
	}
	return a.tType.elemType.celValue(a.get(i))
}

func (a *baseArray) Iterator() traits.Iterator {
	return &baseArrayIterator{
		baseVal: &baseVal{},
		getter:  a.Get,
		sz:      a.size(),
	}
}

func (a *baseArray) Size() ref.Val {
	return types.Int(a.size())
}

type boolArray struct {
	value []bool
}

func (a *boolArray) get(idx int) interface{} {
	return a.value[idx]
}

func (a *boolArray) size() int {
	return len(a.value)
}

type bytesArray struct {
	value [][]byte
}

func (a *bytesArray) get(idx int) interface{} {
	return a.value[idx]
}

func (a *bytesArray) size() int {
	return len(a.value)
}

type doubleArray struct {
	value []float64
}

func (a *doubleArray) get(idx int) interface{} {
	return a.value[idx]
}

func (a *doubleArray) size() int {
	return len(a.value)
}

type floatArray struct {
	value []float32
}

func (a *floatArray) get(idx int) interface{} {
	return a.value[idx]
}

func (a *floatArray) size() int {
	return len(a.value)
}

type ifaceArray struct {
	value []interface{}
}

func (a *ifaceArray) get(idx int) interface{} {
	return a.value[idx]
}

func (a *ifaceArray) size() int {
	return len(a.value)
}

type intArray struct {
	value []int
}

func (a *intArray) get(idx int) interface{} {
	return a.value[idx]
}

func (a *intArray) size() int {
	return len(a.value)
}

type strArray struct {
	value []string
}

func (a *strArray) get(idx int) interface{} {
	return a.value[idx]
}

func (a *strArray) size() int {
	return len(a.value)
}

type baseArrayIterator struct {
	*baseVal
	getter func(idx ref.Val) ref.Val
	sz     int
	idx    int
}

func (it *baseArrayIterator) HasNext() ref.Val {
	if it.idx < it.sz {
		return types.True
	}
	return types.False
}

func (it *baseArrayIterator) Next() ref.Val {
	v := it.getter(types.Int(it.idx))
	it.idx++
	return v
}

func (it *baseArrayIterator) Type() ref.Type {
	return types.IteratorType
}

type mapper interface {
	find(key string) (interface{}, bool)
	keys() []interface{}
	size() int
}

type baseMap struct {
	*baseVal
	mapper
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
	k, isStr := key.(types.String)
	if !isStr {
		return types.ValOrErr(key, "unsupported key: %v", key), true
	}
	et := m.tType.elemType
	ft, found := m.tType.fields[string(k)]
	if !found && et == nil {
		return nil, false
	}
	if found {
		et = ft
	}
	v, found := m.find(string(k))
	if found {
		return et.celValue(v), true
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
	return &baseMapIterator{
		baseVal: &baseVal{},
		keys:    m.keys(),
	}
}

func (m *baseMap) Size() ref.Val {
	return types.Int(m.size())
}

type ifaceMap struct {
	value map[interface{}]interface{}
}

func (m *ifaceMap) find(key string) (interface{}, bool) {
	v, found := m.value[key]
	return v, found
}

func (m *ifaceMap) keys() []interface{} {
	sz := m.size()
	keys := make([]interface{}, sz, sz)
	i := 0
	for k := range m.value {
		keys[i] = k
		i++
	}
	return keys
}

func (m *ifaceMap) size() int {
	return len(m.value)
}

type strMap struct {
	value map[string]interface{}
}

func (m *strMap) find(key string) (interface{}, bool) {
	v, found := m.value[key]
	return v, found
}

func (m *strMap) keys() []interface{} {
	sz := len(m.value)
	keys := make([]interface{}, sz, sz)
	i := 0
	for k := range m.value {
		keys[i] = k
		i++
	}
	return keys
}

func (m *strMap) size() int {
	return len(m.value)
}

type baseMapIterator struct {
	*baseVal
	keys []interface{}
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
	return types.String(key.(string))
}

func (it *baseMapIterator) Type() ref.Type {
	return types.IteratorType
}

type propertyFactory func(*tmplType, interface{}) ref.Val

func boolProperty(tk *tmplType, val interface{}) ref.Val {
	return types.Bool(val.(bool))
}

func bytesProperty(tk *tmplType, val interface{}) ref.Val {
	switch v := val.(type) {
	case string:
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return types.NewErr("%v", err)
		}
		return types.Bytes(b)
	case []byte:
		return types.Bytes(v)
	}
	return types.NewErr("unable to convert to number: %v", val)
}

func integerProperty(tk *tmplType, val interface{}) ref.Val {
	switch v := val.(type) {
	case int:
		return types.Int(v)
	}
	return types.NewErr("unable to convert to integer: %v", val)
}

func numberProperty(tk *tmplType, val interface{}) ref.Val {
	switch v := val.(type) {
	case int:
		return types.Double(v)
	case float32:
		return types.Double(v)
	case float64:
		return types.Double(v)
	}
	return types.NewErr("unable to convert to number: %v", val)
}

func stringProperty(tk *tmplType, val interface{}) ref.Val {
	switch v := val.(type) {
	case string:
		return types.String(v)
	}
	return types.NewErr("unable to convert to string: %v", val)
}

var (
	propertyFactories = map[string]propertyFactory{
		"boolean": boolProperty,
		"bytes":   bytesProperty,
		"integer": integerProperty,
		"number":  numberProperty,
		"string":  stringProperty,
	}
)
