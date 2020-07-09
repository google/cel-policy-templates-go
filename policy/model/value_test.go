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
	"reflect"
	"testing"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/traits"
)

func Test_ListValue_Add(t *testing.T) {
	lv := NewListValue()
	lv.Append(NewDynValue(1, "first"))
	ov := NewListValue()
	ov.Append(NewDynValue(2, "second"))
	ov.Append(NewDynValue(3, "third"))
	llv := NewListValue()
	llv.Append(NewDynValue(4, lv))
	lov := NewListValue()
	lov.Append(NewDynValue(5, ov))
	var v traits.Lister = llv.Add(lov).(traits.Lister)
	if v.Size() != types.Int(2) {
		t.Errorf("got list size %d, wanted 2", v.Size())
	}
	complex, err := v.ConvertToNative(reflect.TypeOf([][]string{}))
	complexList := complex.([][]string)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(complexList, [][]string{{"first"}, {"second", "third"}}) {
		t.Errorf("got %v, wanted [['first'], ['second', 'third']]", complexList)
	}
}

func Test_ListValue_ConvertToNative(t *testing.T) {
	lv := NewListValue()
	none, err := lv.ConvertToNative(reflect.TypeOf([]interface{}{}))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(none, []interface{}{}) {
		t.Errorf("got %v, wanted empty list", none)
	}
	lv.Append(NewDynValue(1, "first"))
	one, err := lv.ConvertToNative(reflect.TypeOf([]string{}))
	oneList := one.([]string)
	if err != nil {
		t.Fatal(err)
	}
	if len(oneList) != 1 {
		t.Errorf("got len(one) == %d, wanted 1", len(oneList))
	}
	if !reflect.DeepEqual(oneList, []string{"first"}) {
		t.Errorf("got %v, wanted string list", oneList)
	}
	ov := NewListValue()
	ov.Append(NewDynValue(2, "second"))
	ov.Append(NewDynValue(3, "third"))
	if ov.Size() != types.Int(2) {
		t.Errorf("got list size %d, wanted 2", ov.Size())
	}
	llv := NewListValue()
	llv.Append(NewDynValue(4, lv))
	llv.Append(NewDynValue(5, ov))
	if llv.Size() != types.Int(2) {
		t.Errorf("got list size %d, wanted 2", llv.Size())
	}
	complex, err := llv.ConvertToNative(reflect.TypeOf([][]string{}))
	complexList := complex.([][]string)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(complexList, [][]string{{"first"}, {"second", "third"}}) {
		t.Errorf("got %v, wanted [['first'], ['second', 'third']]", complexList)
	}
}

func Test_MapValue_ConvertToNative(t *testing.T) {
	mv := NewMapValue()
	none, err := mv.ConvertToNative(reflect.TypeOf(map[string]interface{}{}))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(none, map[string]interface{}{}) {
		t.Errorf("got %v, wanted empty map", none)
	}
	none, err = mv.ConvertToNative(reflect.TypeOf(map[interface{}]interface{}{}))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(none, map[interface{}]interface{}{}) {
		t.Errorf("got %v, wanted empty map", none)
	}
	mv.AddField(NewField(1, "Test"))
	tst, _ := mv.GetField("Test")
	tst.Ref = NewDynValue(2, uint64(12))
	mv.AddField(NewField(3, "Check"))
	chk, _ := mv.GetField("Check")
	chk.Ref = NewDynValue(4, uint64(34))
	if mv.Size() != types.Int(2) {
		t.Errorf("got size %d, wanted 2", mv.Size())
	}
	if mv.Contains(types.String("Test")) != types.True {
		t.Error("key 'Test' not found")
	}
	if mv.Contains(types.String("Check")) != types.True {
		t.Error("key 'Check' not found")
	}
	if mv.Contains(types.String("Checked")) != types.False {
		t.Error("key 'Checked' found, wanted not found")
	}
	it := mv.Iterator()
	for it.HasNext() == types.True {
		k := it.Next()
		v := mv.Get(k)
		if k == types.String("Test") && v != types.Uint(12) {
			t.Errorf("key 'Test' not equal to 12u")
		}
		if k == types.String("Check") && v != types.Uint(34) {
			t.Errorf("key 'Check' not equal to 34u")
		}
	}
	mpStrUint, err := mv.ConvertToNative(reflect.TypeOf(map[string]uint64{}))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(mpStrUint, map[string]uint64{
		"Test":  uint64(12),
		"Check": uint64(34),
	}) {
		t.Errorf("got %v, wanted {'Test': 12u, 'Check': 34u}", mpStrUint)
	}
	tstStr, err := mv.ConvertToNative(reflect.TypeOf(&tstStruct{}))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(tstStr, &tstStruct{
		Test:  uint64(12),
		Check: uint64(34),
	}) {
		t.Errorf("got %v, wanted tstStruct{Test: 12u, Check: 34u}", tstStr)
	}
}

type tstStruct struct {
	Test  uint64
	Check uint64
}
