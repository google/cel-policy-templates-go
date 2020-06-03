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

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"

	dpb "github.com/golang/protobuf/ptypes/duration"
	tpb "github.com/golang/protobuf/ptypes/timestamp"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

func NewListType(elem *DeclType) *DeclType {
	return &DeclType{
		name:      "list",
		ElemType:  elem,
		exprType:  decls.NewListType(elem.ExprType()),
		zeroValue: NewListValue(),
	}
}

func NewMapType(key, elem *DeclType) *DeclType {
	return &DeclType{
		name:      "map",
		KeyType:   key,
		ElemType:  elem,
		exprType:  decls.NewMapType(key.ExprType(), elem.ExprType()),
		zeroValue: NewMapValue(),
	}
}

func NewObjectType(name string, fields map[string]*DeclType) *DeclType {
	t := &DeclType{
		name:      name,
		Fields:    fields,
		exprType:  decls.NewObjectType(name),
		traitMask: traits.FieldTesterType | traits.IndexerType,
	}
	t.zeroValue = NewObjectValue(t)
	return t
}

func NewObjectTypeRef(name string) *DeclType {
	t := &DeclType{
		name:      name,
		exprType:  decls.NewObjectType(name),
		traitMask: traits.FieldTesterType | traits.IndexerType,
	}
	return t
}

func NewTypeParam(name string) *DeclType {
	return &DeclType{
		name:      name,
		TypeParam: true,
		exprType:  decls.NewTypeParamType(name),
	}
}

func newSimpleType(name string, exprType *exprpb.Type, zeroVal ref.Val) *DeclType {
	return &DeclType{
		name:      name,
		exprType:  exprType,
		zeroValue: zeroVal,
	}
}

type DeclType struct {
	name      string
	Fields    map[string]*DeclType
	KeyType   *DeclType
	ElemType  *DeclType
	TypeParam bool
	Metadata  map[string]string

	exprType  *exprpb.Type
	traitMask int
	zeroValue ref.Val
}

func (t *DeclType) AssignTypeName(name string) error {
	if !t.IsObject() {
		return fmt.Errorf(
			"type names may only be assigned to objects: type=%v, name=%s",
			t, name)
	}
	t.name = name
	t.exprType = decls.NewObjectType(name)
	return nil
}

func (t *DeclType) ExprType() *exprpb.Type {
	return t.exprType
}

func (t *DeclType) HasTrait(trait int) bool {
	if t.traitMask&trait == trait {
		return true
	}
	if t.zeroValue == nil {
		return false
	}
	return t.zeroValue.Type().HasTrait(trait)
}

func (t *DeclType) IsList() bool {
	return t.KeyType == nil && t.ElemType != nil
}

func (t *DeclType) IsMap() bool {
	return t.KeyType != nil && t.ElemType != nil
}

func (t *DeclType) IsObject() bool {
	return t.Fields != nil
}

func (t *DeclType) String() string {
	return t.name
}

func (t *DeclType) TypeName() string {
	return t.name
}

func (t *DeclType) Zero() ref.Val {
	return t.zeroValue
}

// NewRuleTypes returns an Open API Schema-based type-system which is CEL compatible.
func NewRuleTypes(kind string,
	schema *OpenAPISchema,
	res Resolver) (*RuleTypes, error) {
	// Note, if the schema indicates that it's actually based on another proto
	// then prefer the proto definition. For expressions in the proto, a new field
	// annotation will be needed to indicate the expected environment and type of
	// the expression.
	schemaTypes, err := newSchemaTypeProvider(kind, schema)
	if err != nil {
		return nil, err
	}
	return &RuleTypes{
		Schema:              schema,
		ruleSchemaDeclTypes: schemaTypes,
		resolver:            res,
	}, nil
}

// RuleTypes extends the CEL ref.TypeProvider interface and provides an Open API Schema-based
// type-system.
type RuleTypes struct {
	ref.TypeProvider
	Schema              *OpenAPISchema
	ruleSchemaDeclTypes *schemaTypeProvider
	typeAdapter         ref.TypeAdapter
	resolver            Resolver
}

// EnvOptions returns a set of cel.EnvOption values which includes the Template's declaration set
// as well as a custom ref.TypeProvider.
//
// Note, the standard declaration set includes 'rule' which is defined as the top-level rule-schema
// type if one is configured.
//
// If the RuleTypes value is nil, an empty []cel.EnvOption set is returned.
func (rt *RuleTypes) EnvOptions(tp ref.TypeProvider) []cel.EnvOption {
	if rt == nil {
		return []cel.EnvOption{}
	}
	var ta ref.TypeAdapter = types.DefaultTypeAdapter
	tpa, ok := tp.(ref.TypeAdapter)
	if ok {
		ta = tpa
	}
	rtWithTypes := &RuleTypes{
		TypeProvider:        tp,
		typeAdapter:         ta,
		Schema:              rt.Schema,
		ruleSchemaDeclTypes: rt.ruleSchemaDeclTypes,
		resolver:            rt.resolver,
	}
	return []cel.EnvOption{
		cel.CustomTypeProvider(rtWithTypes),
		cel.CustomTypeAdapter(rtWithTypes),
		cel.Declarations(
			decls.NewIdent("rule", rt.ruleSchemaDeclTypes.root.ExprType(), nil),
		),
	}
}

// FindType attempts to resolve the typeName provided from the template's rule-schema, or if not
// from the embedded ref.TypeProvider.
//
// FindType overrides the default type-finding behavior of the embedded TypeProvider.
//
// Note, when the type name is based on the Open API Schema, the name will reflect the object path
// where the type definition appears.
func (rt *RuleTypes) FindType(typeName string) (*exprpb.Type, bool) {
	if rt == nil {
		return nil, false
	}
	declType, found := rt.findSchemaType(typeName)
	if found {
		return declType.ExprType(), found
	}
	return rt.TypeProvider.FindType(typeName)
}

// FindFieldType returns a field type given a type name and field name, if found.
//
// Note, the type name for an Open API Schema type is likely to be its qualified object path.
// If, in the future an object instance rather than a type name were provided, the field
// resolution might more accurately reflect the expected type model. However, in this case
// concessions were made to align with the existing CEL interfaces.
func (rt *RuleTypes) FindFieldType(typeName, fieldName string) (*ref.FieldType, bool) {
	st, found := rt.findSchemaType(typeName)
	if !found {
		return rt.TypeProvider.FindFieldType(typeName, fieldName)
	}

	f, found := st.Fields[fieldName]
	if found {
		return &ref.FieldType{
			Type: f.ExprType(),
		}, true
	}
	// This could be a dynamic map.
	if st.IsMap() {
		return &ref.FieldType{
			Type: st.ElemType.ExprType(),
		}, true
	}
	return nil, false
}

// ConvertToRule transforms an untyped DynValue into a typed object.
//
// Conversion is done deeply and will traverse the object graph represented by the dyn value.
func (rt *RuleTypes) ConvertToRule(dyn *DynValue) Rule {
	ruleSchemaType := rt.ruleSchemaDeclTypes.root
	// TODO: handle conversions to protobuf types.
	dyn = rt.convertToCustomType(dyn, ruleSchemaType)
	return &CustomRule{DynValue: dyn}
}

// NativeToValue is an implementation of the ref.TypeAdapater interface which supports conversion
// of policy template values to CEL ref.Val instances.
func (rt *RuleTypes) NativeToValue(val interface{}) ref.Val {
	switch v := val.(type) {
	case *CustomRule:
		return v.ExprValue()
	default:
		return rt.typeAdapter.NativeToValue(val)
	}
}

func (rt *RuleTypes) findSchemaType(typeName string) (*DeclType, bool) {
	declType, found := rt.ruleSchemaDeclTypes.types[typeName]
	if found {
		return declType, true
	}
	declType, found = rt.resolver.FindType(typeName)
	if found {
		return declType, true
	}
	return nil, false
}

func (rt *RuleTypes) convertToCustomType(dyn *DynValue,
	declType *DeclType) *DynValue {
	switch v := dyn.Value.(type) {
	case *MapValue:
		if declType.IsObject() {
			obj := v.ConvertToObject(declType)
			for name, f := range obj.fieldMap {
				fieldType := declType.Fields[name]
				f.Ref = rt.convertToCustomType(f.Ref, fieldType)
			}
			dyn.Value = obj
			return dyn
		}
		// TODO: handle complex map types which have non-string keys.
		fieldType := declType.ElemType
		for _, f := range v.fieldMap {
			f.Ref = rt.convertToCustomType(f.Ref, fieldType)
		}
		return dyn
	case *ListValue:
		for i := 0; i < len(v.Entries); i++ {
			elem := v.Entries[i]
			elem = rt.convertToCustomType(elem, declType.ElemType)
			v.Entries[i] = elem
		}
		return dyn
	default:
		return dyn
	}
}

func newSchemaTypeProvider(kind string, schema *OpenAPISchema) (*schemaTypeProvider, error) {
	root := schema.DeclType()
	root.name = kind
	types := map[string]*DeclType{
		kind: root,
	}
	err := buildDeclTypes(kind, root, types)
	if err != nil {
		return nil, err
	}
	return &schemaTypeProvider{
		root:  root,
		types: types,
	}, nil
}

type schemaTypeProvider struct {
	root  *DeclType
	types map[string]*DeclType
}

func buildDeclTypes(path string, t *DeclType, types map[string]*DeclType) error {
	// Ensure object types are properly named according to where they appear in the schema.
	if t.IsObject() {
		// Hack to ensure that names are uniquely qualified and work well with the type
		// resolution steps which require fully qualified type names for field resolution
		// to function properly.
		err := t.AssignTypeName(path)
		if err != nil {
			return err
		}
		types[path] = t
		for name, declType := range t.Fields {
			if declType == nil {
				continue
			}
			fieldPath := fmt.Sprintf("%s.%s", path, name)
			err := buildDeclTypes(fieldPath, declType, types)
			if err != nil {
				return err
			}
			types[fieldPath] = declType
			return nil
		}
	}
	// Map element properties to type names if needed.
	if t.IsMap() {
		mapElemPath := fmt.Sprintf("%s.@elem", path)
		return buildDeclTypes(mapElemPath, t.ElemType, types)
	}
	// List element properties.
	if t.IsList() {
		listIdxPath := fmt.Sprintf("%s.@idx", path)
		return buildDeclTypes(listIdxPath, t.ElemType, types)
	}
	return nil
}

var (
	// AnyType is equivalent to the CEL 'protobuf.Any' type in that the value may have any of the
	// types supported by CEL Policy Templates.
	AnyType = newSimpleType("any", decls.Any, nil)

	// BoolType is equivalent to the CEL 'bool' type.
	BoolType = newSimpleType("bool", decls.Bool, types.False)

	// BytesType is equivalent to the CEL 'bytes' type.
	BytesType = newSimpleType("bytes", decls.Bytes, types.Bytes([]byte{}))

	// DoubleType is equivalent to the CEL 'double' type which is a 64-bit floating point value.
	DoubleType = newSimpleType("double", decls.Double, types.Double(0))

	// DurationType is equivalent to the CEL 'duration' type.
	DurationType = newSimpleType("duration", decls.Duration,
		types.Duration{Duration: &dpb.Duration{}})

	DynType = newSimpleType("dyn", decls.Dyn, nil)

	// IntType is equivalent to the CEL 'int' type which is a 64-bit signed int.
	IntType = newSimpleType("int", decls.Int, types.IntZero)

	// NullType is equivalent to the CEL 'null_type'.
	NullType = newSimpleType("null_type", decls.Null, types.NullValue)

	// StringType is equivalent to the CEL 'string' type which is expected to be a UTF-8 string.
	// StringType values may either be string literals or expression strings.
	StringType = newSimpleType("string", decls.String, types.String(""))

	// PlainTextType is equivalent to the CEL 'string' type, but which has been specifically
	// designated as a string literal.
	PlainTextType = newSimpleType("string_lit", decls.String, types.String(""))

	// TimestampType corresponds to the well-known protobuf.Timestamp type supported within CEL.
	TimestampType = newSimpleType("timestamp", decls.Timestamp,
		types.Timestamp{Timestamp: &tpb.Timestamp{}})

	// UintType is equivalent to the CEL 'uint' type.
	UintType = newSimpleType("uint", decls.Uint, types.Uint(0))

	// ListType is equivalent to the CEL 'list' type.
	ListType = NewListType(AnyType)

	// MapType is equivalent to the CEL 'map' type.
	MapType = NewMapType(AnyType, AnyType)
)
