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
)

func TestSchema_DeclTypes(t *testing.T) {
	ts := testSchema()
	cust := ts.DeclType()
	if cust.TypeName() != "CustomObject" {
		t.Errorf("incorrect type name, got %v, wanted CustomObject", cust.TypeName())
	}
	if len(cust.Fields) != 3 {
		t.Errorf("incorrect number of fields, got %d, wanted 3", len(cust.Fields))
	}
	for _, f := range cust.Fields {
		prop, found := ts.FindProperty(f.Name)
		if !found {
			t.Errorf("type field not found in schema, field: %s", f.Name)
		}
		fdv := f.DefaultValue()
		if prop.DefaultValue != nil {
			pdv := types.DefaultTypeAdapter.NativeToValue(prop.DefaultValue)
			if !reflect.DeepEqual(fdv, pdv) {
				t.Errorf("field and schema do not agree on default value, field: %s", f.Name)
			}
		}
		if prop.Enum == nil && len(f.EnumValues()) != 0 {
			t.Errorf("field had more enum values than the property. field: %s", f.Name)
		}
		if prop.Enum != nil {
			fevs := f.EnumValues()
			for _, fev := range fevs {
				found := false
				for _, pev := range prop.Enum {
					pev = types.DefaultTypeAdapter.NativeToValue(pev)
					if reflect.DeepEqual(fev, pev) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf(
						"could not find field enum value in property definition. field: %s, enum: %v",
						f.Name, fev)
				}
			}
		}
	}
	for _, name := range ts.Required {
		df, found := cust.FindField(name)
		if !found {
			t.Errorf("custom type missing required field. field=%s", name)
		}
		if !df.Required {
			t.Errorf("field marked as required in schema, but optional in type. field=%s", df.Name)
		}
	}
}

func testSchema() *OpenAPISchema {
	// Manual construction of a schema with the following definition:
	//
	// schema:
	//   type: object
	//   metadata:
	//     custom_type: "CustomObject"
	//   required:
	//     - name
	//     - value
	//   properties:
	//     name:
	//       type: string
	//     nested:
	//       type: object
	//       properties:
	//         subname:
	//           type: string
	//         flags:
	//           type: object
	//           additionalProperties:
	//             type: boolean
	//         dates:
	//           type: array
	//           items:
	//             type: string
	//             format: date-time
	//     value:
	//       type: integer
	//       format: int64
	//       default: 1
	//       enum: [1,2,3]
	nameField := NewOpenAPISchema()
	nameField.Type = "string"
	valueField := NewOpenAPISchema()
	valueField.Type = "integer"
	valueField.Format = "int64"
	valueField.DefaultValue = int64(1)
	valueField.Enum = []interface{}{int64(1), int64(2), int64(3)}
	nestedObjField := NewOpenAPISchema()
	nestedObjField.Type = "object"
	nestedObjField.Properties["subname"] = NewOpenAPISchema()
	nestedObjField.Properties["subname"].Type = "string"
	nestedObjField.Properties["flags"] = NewOpenAPISchema()
	nestedObjField.Properties["flags"].Type = "object"
	nestedObjField.Properties["flags"].AdditionalProperties = NewOpenAPISchema()
	nestedObjField.Properties["flags"].AdditionalProperties.Type = "boolean"
	nestedObjField.Properties["dates"] = NewOpenAPISchema()
	nestedObjField.Properties["dates"].Type = "array"
	nestedObjField.Properties["dates"].Items = NewOpenAPISchema()
	nestedObjField.Properties["dates"].Items.Type = "string"
	nestedObjField.Properties["dates"].Items.Format = "date-time"
	ts := NewOpenAPISchema()
	ts.Type = "object"
	ts.Metadata["custom_type"] = "CustomObject"
	ts.Required = []string{"name", "value"}
	ts.Properties["name"] = nameField
	ts.Properties["value"] = valueField
	ts.Properties["nested"] = nestedObjField
	return ts
}
