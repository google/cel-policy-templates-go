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
	"fmt"

	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"

	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

type templateModel struct {
	name  string
	root  *tmplType
	types map[string]*tmplType
}

func unmarshalTemplateModel(f *file) (*templateModel, error) {
	tmpl := &tmplCrd{}
	err := f.unmarshalYaml(tmpl)
	if err != nil {
		return nil, err
	}
	templateType := tmpl.Metadata["name"]
	root := &tmplType{
		kind:   templateType,
		fields: map[string]*tmplType{},
	}
	typeKinds := buildTemplate(root.kind, root, tmpl.Spec)
	typeKinds[root.kind] = root
	return &templateModel{
		name:  templateType,
		root:  root,
		types: typeKinds,
	}, nil
}

func (t *templateModel) bind(provider ref.TypeProvider) (*template, error) {
	return &template{
		TypeProvider:  provider,
		templateModel: t,
	}, nil
}

func (t *templateModel) String() string {
	return fmt.Sprintf("{%v}", t.types)
}

type template struct {
	ref.TypeProvider
	*templateModel
}

func (tmpl *template) FindType(typeName string) (*exprpb.Type, bool) {
	simple, found := simpleExprTypes[typeName]
	if found {
		return simple, true
	}
	tk, found := tmpl.types[typeName]
	if found {
		return tk.exprType(), true
	}
	return tmpl.TypeProvider.FindType(typeName)
}

func (tmpl *template) FindFieldType(typeName, fieldName string) (*ref.FieldType, bool) {
	tk, found := tmpl.types[typeName]
	if found {
		f, found := tk.fields[fieldName]
		if found {
			return f.fieldType(), true
		}
		if tk.isMap() {
			return &ref.FieldType{
				SupportsPresence: true,
				Type:             tk.elemType.exprType(),
			}, true
		}
		return nil, false
	}
	return tmpl.TypeProvider.FindFieldType(typeName, fieldName)
}

type tmplType struct {
	// name is a conjunction of the top-level type and the field path for
	// dynamic objects. Alternatively, if the template refers to another
	// type, this is only marked on the field and the type structure is not
	// replicated.
	name string

	// kind of the object
	kind string

	// Lists will specify an elem type.
	// Maps will specify a key and elem type.
	// Static objects will only specify fields.
	// Dynamic objects will specify fields as well as a key and element type.
	keyType  *tmplType
	elemType *tmplType
	fields   map[string]*tmplType

	// Allow for the specification of proto message type or environment within
	// metadata.
	metadata map[string]interface{}
}

func (tType *tmplType) HasTrait(trait int) bool {
	return typeTraits[tType.kind]&trait == trait
}

// TypeName returns the qualified type name of the type.
func (tType *tmplType) TypeName() string {
	if tType.name != "" {
		return tType.name
	}
	return tType.kind
}

func (tType *tmplType) celValue(value interface{}) ref.Val {
	if value == nil {
		return tType.defaultValue()
	}
	fac, found := propertyFactories[tType.kind]
	if found {
		return fac(tType, value)
	}
	base := &baseVal{value: value, tType: tType}
	if tType.isList() {
		switch a := value.(type) {
		case []bool:
			return &baseArray{
				baseVal: base,
				lister:  &boolArray{value: a},
			}
		case [][]byte:
			return &baseArray{
				baseVal: base,
				lister:  &bytesArray{value: a},
			}
		case []float32:
			return &baseArray{
				baseVal: base,
				lister:  &floatArray{value: a},
			}
		case []float64:
			return &baseArray{
				baseVal: base,
				lister:  &doubleArray{value: a},
			}
		case []int:
			return &baseArray{
				baseVal: base,
				lister:  &intArray{value: a},
			}
		case []interface{}:
			return &baseArray{
				baseVal: base,
				lister:  &ifaceArray{value: a},
			}
		case []string:
			return &baseArray{
				baseVal: base,
				lister:  &strArray{value: a},
			}
		default:
			return types.NewErr("unsupported list type: %T", value)
		}
	}
	switch m := value.(type) {
	case map[string]interface{}:
		return &baseMap{
			baseVal: base,
			mapper:  &strMap{value: m},
		}
	case map[interface{}]interface{}:
		return &baseMap{
			baseVal: base,
			mapper:  &ifaceMap{value: m},
		}
	default:
		return types.NewErr("unsupported map type: %T", value)
	}
}

func (tType *tmplType) defaultValue() ref.Val {
	val, found := typeDefaults[tType.kind]
	if found {
		return val
	}
	// TODO: implement for list, maps, and objects, likely requires support
	// for NativeToValue on the template.
	switch tType.kind {
	case "object":
		return tType.celValue(map[interface{}]interface{}{})
	case "array":
		return tType.celValue([]interface{}{})
	}
	return types.NewErr("value does not have default: %s", tType.TypeName())
}

func (tType *tmplType) exprType() *exprpb.Type {
	set, found := simpleExprTypes[tType.kind]
	if found {
		return set
	}
	if tType.isList() {
		return decls.NewListType(tType.elemType.exprType())
	}
	// otherwise, this is a map or object (ignoring date-time for now)
	if tType.isMap() && !tType.isObject() {
		return decls.NewMapType(tType.keyType.exprType(), tType.elemType.exprType())
	}
	return decls.NewObjectType(tType.kind)
}

func (tType *tmplType) fieldType() *ref.FieldType {
	return &ref.FieldType{
		SupportsPresence: true,
		Type:             tType.exprType(),
	}
}

func (tType *tmplType) isList() bool {
	return tType.keyType == nil && tType.elemType != nil
}

func (tType *tmplType) isMap() bool {
	return tType.keyType != nil && tType.keyType.kind == "string" &&
		tType.elemType != nil
}

func (tType *tmplType) isObject() bool {
	return len(tType.fields) > 0
}

func buildTemplate(parentType string, tType *tmplType, p *tmplPropYaml) map[string]*tmplType {
	fieldTypes := map[string]*tmplType{}
	// Object
	for name, val := range p.Properties {
		field := &tmplType{kind: val.Type}
		if val.Type == "object" || val.Type == "array" {
			fieldType := fmt.Sprintf("%s.%s", parentType, name)
			innerTypes := buildTemplate(fieldType, field, val)
			for k, v := range innerTypes {
				fieldTypes[k] = v
			}
			fieldTypes[fieldType] = field
		}
		tType.fields[name] = field
	}
	// Map
	if p.AdditionalProperties != nil {
		elemTag := p.AdditionalProperties.Type
		tType.keyType = &tmplType{kind: "string"}
		tType.elemType = &tmplType{kind: elemTag}
		if elemTag == "object" || elemTag == "array" {
			fieldType := fmt.Sprintf("%s.%s", parentType, "@additionalProperties")
			innerTypes := buildTemplate(fieldType, tType.elemType, p.AdditionalProperties)
			for k, v := range innerTypes {
				fieldTypes[k] = v
			}
			fieldTypes[fieldType] = tType.elemType
		}
	}
	// Array
	if p.Items != nil {
		elemTag := p.Items.Type
		tType.elemType = &tmplType{kind: elemTag}
		if elemTag == "object" || elemTag == "array" {
			fieldType := fmt.Sprintf("%s.%s", parentType, "@items")
			innerTypes := buildTemplate(fieldType, tType.elemType, p.AdditionalProperties)
			for k, v := range innerTypes {
				fieldTypes[k] = v
			}
			fieldTypes[fieldType] = tType.elemType
		}
	}
	return fieldTypes
}

type tmplCrd struct {
	APIVersion string            `yaml:"apiVersion"`
	Kind       string            `yaml:"kind"`
	Metadata   map[string]string `yaml:"metadata"`
	Spec       *tmplPropYaml     `yaml:"spec"`
}

type tmplPropYaml struct {
	Type                 string                   `yaml:"type"`
	Format               string                   `yaml:"format,omitempty"`
	Items                *tmplPropYaml            `yaml:"items,omitempty"`
	Properties           map[string]*tmplPropYaml `yaml:"properties,omitempty"`
	AdditionalProperties *tmplPropYaml            `yaml:"additionalProperties,omitempty"`
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
		"boolean": traits.ComparerType | traits.NegatorType,
		"number":  numericTraits,
		"integer": numericTraits,
		"string":  bytesTraits,
		"byte":    bytesTraits,
		"array":   containerTraits | traits.AdderType,
		"object":  containerTraits | traits.FieldTesterType,
	}
	typeDefaults = map[string]ref.Val{
		"boolean": types.False,
		"number":  types.Double(0),
		"integer": types.Int(0),
		"string":  types.String(""),
		"byte":    types.Bytes([]byte{}),
	}
	simpleExprTypes = map[string]*exprpb.Type{
		"boolean": decls.Bool,
		"number":  decls.Double,
		"integer": decls.Int,
		"string":  decls.String,
		"byte":    decls.Bytes,
	}
)
