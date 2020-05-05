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
	types := map[string]*schemaType{
		kind: root,
	}
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

func (st *schemaType) ModelType() string {
	return st.schema.ModelType()
}

func (st *schemaType) ExprType() *exprpb.Type {
	ct := st.ModelType()
	val, found := simpleExprTypes[ct]
	if found {
		return val
	}
	if ct == "any" {
		return decls.Dyn
	}
	if ct == ListType {
		return decls.NewListType(st.elemType.ExprType())
	}
	if ct == MapType && st.schema.AdditionalProperties != nil {
		return decls.NewMapType(st.keyType.ExprType(), st.elemType.ExprType())
	}
	// This is a hack around the fact that field types are resolved relative to a type name.
	// In the absence of a proper type name for an element of an Open API Schema definition,
	// the object path used to get to the field is used. This could be addressed at a CEL API
	// level with a change to the TypeProvider to support field resolution from a type
	return decls.NewObjectType(st.objectPath)
}

func (st *schemaType) HasTrait(trait int) bool {
	return typeTraits[st.ModelType()]&trait == trait
}

func (st *schemaType) TypeName() string {
	ct := st.ModelType()
	switch ct {
	case "any":
		return st.objectPath
	case MapType:
		// Hack for making sure field types can be resolved.
		if st.isObject() {
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
		fieldModelType := def.ModelType()
		if fieldModelType == MapType || fieldModelType == ListType {
			buildSchemaTypes(fieldType, types)
			types[fieldType.objectPath] = fieldType
		}
	}
	// Additional map properties
	if t.schema.AdditionalProperties != nil {
		stringKey := NewOpenAPISchema()
		stringKey.Type = StringType
		t.keyType = &schemaType{
			schema:     stringKey,
			objectPath: fmt.Sprintf("%s.@key", t.objectPath),
		}
		t.elemType = &schemaType{
			schema:     t.schema.AdditionalProperties,
			objectPath: fmt.Sprintf("%s.@prop", t.objectPath),
		}
		fieldModelType := t.elemType.ModelType()
		if fieldModelType == MapType || fieldModelType == ListType {
			buildSchemaTypes(t.elemType, types)
			types[t.elemType.objectPath] = t.elemType
		}
	}
	// List element properties
	if t.schema.Items != nil {
		t.elemType = &schemaType{
			schema:     t.schema.Items,
			objectPath: fmt.Sprintf("%s.@idx", t.objectPath),
		}
		elemModelType := t.elemType.ModelType()
		if elemModelType == MapType || elemModelType == ListType {
			buildSchemaTypes(t.elemType, types)
			types[t.elemType.objectPath] = t.elemType
		}
	}
}

const (
	// AnyType is equivalent to the CEL 'dyn' type in that the value may have any of the types
	// supported by CEL Policy Templates.
	AnyType = "any"

	// ExprType represents a compiled CEL expression value.
	ExprType = "expr"

	// BoolType is equivalent to the CEL 'bool' type.
	BoolType = "bool"

	// BytesType is equivalent to the CEL 'bytes' type.
	BytesType = "bytes"

	// DoubleType is equivalent to the CEL 'double' type which is a 64-bit floating point value.
	DoubleType = "double"

	// IntType is equivalent to the CEL 'int' type which is a 64-bit signed int.
	IntType = "int"

	// NullType is equivalent to the CEL 'null_type'.
	NullType = "null_type"

	// StringType is equivalent to the CEL 'string' type which is expected to be a UTF-8 string.
	// StringType values may either be string literals or expression strings.
	StringType = "string"

	// PlainTextType is equivalent to the CEL 'string' type, but which has been specifically
	// designated as a string literal.
	PlainTextType = "string_lit"

	// TimestampType corresponds to the well-known protobuf.Timestamp type supported within CEL.
	TimestampType = "timestamp"

	// UintType is equivalent to the CEL 'uint' type.
	UintType = "uint"

	// ListType is equivalent to the CEL 'list' type.
	ListType = "list"

	// MapType is equivalent to the CEL 'map' type.
	MapType = "map"
)

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
		BoolType:   traits.ComparerType | traits.NegatorType,
		BytesType:  bytesTraits,
		DoubleType: numericTraits,
		IntType:    numericTraits,
		StringType: bytesTraits,
		ListType:   containerTraits | traits.AdderType,
		MapType:    containerTraits,
	}
	typeDefaults = map[string]ref.Val{
		BoolType:   types.False,
		BytesType:  types.Bytes([]byte{}),
		DoubleType: types.Double(0),
		IntType:    types.Int(0),
		StringType: types.String(""),
		ListType:   NewListValue(),
		MapType:    NewMapValue(),
	}
	simpleExprTypes = map[string]*exprpb.Type{
		BoolType:      decls.Bool,
		BytesType:     decls.Bytes,
		DoubleType:    decls.Double,
		NullType:      decls.Null,
		IntType:       decls.Int,
		StringType:    decls.String,
		TimestampType: decls.Timestamp,
	}
)
