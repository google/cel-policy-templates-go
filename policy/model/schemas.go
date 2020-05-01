// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package model

import (
	"strings"

	"gopkg.in/yaml.v3"
)

// NewOpenAPISchema returns an empty instance of an OpenAPISchema object.
func NewOpenAPISchema() *OpenAPISchema {
	return &OpenAPISchema{
		Enum:       []interface{}{},
		Metadata:   map[string]string{},
		Properties: map[string]*OpenAPISchema{},
		Required:   []string{},
	}
}

// OpenAPISchema declares a struct capable of representing a subset of Open API Schemas
// supported by Kubernetes which can also be specified within Protocol Buffers.
//
// There are a handful of notable differences:
// - The validating constructs `allOf`, `anyOf`, `oneOf`, `not`, and type-related restrictsion are
//   not supported as they can be better validated in the template 'validator' block.
// - The $ref field supports references to other schema definitions, but such aliases
//   should be removed before being serialized.
// - The `additionalProperties` and `properties` fields are not currently mutually exclusive as is
//   the case for Kubernetes.
//
// See: https://kubernetes.io/docs/tasks/access-kubernetes-api/custom-resources/custom-resource-definitions/#validation
type OpenAPISchema struct {
	Title                string                    `yaml:"title,omitempty"`
	Description          string                    `yaml:"description,omitempty"`
	Type                 string                    `yaml:"type,omitempty"`
	TypeRef              string                    `yaml:"$ref,omitempty"`
	DefaultValue         interface{}               `yaml:"default,omitempty"`
	Enum                 []interface{}             `yaml:"enum,omitempty"`
	Format               string                    `yaml:"format,omitempty"`
	Items                *OpenAPISchema            `yaml:"items,omitempty"`
	Metadata             map[string]string         `yaml:"metadata,omitempty"`
	Required             []string                  `yaml:"required,omitempty"`
	Properties           map[string]*OpenAPISchema `yaml:"properties,omitempty"`
	AdditionalProperties *OpenAPISchema            `yaml:"additionalProperties,omitempty"`
}

// ModelType returns the CEL Policy Templates type name associated with the schema element.
func (s *OpenAPISchema) ModelType() string {
	commonType := openAPISchemaTypes[s.Type]
	switch commonType {
	case "string":
		switch s.Format {
		case "byte", "binary":
			return BytesType
		case "date", "date-time":
			return TimestampType
		}
	}
	return commonType
}

// Equal returns whether two schemas are equal.
func (s *OpenAPISchema) Equal(other *OpenAPISchema) bool {
	if s.ModelType() != other.ModelType() {
		return false
	}
	// perform deep equality here.
	switch s.ModelType() {
	case "any":
		return false
	case MapType:
		if len(s.Properties) != len(other.Properties) {
			return false
		}
		for prop, nested := range s.Properties {
			otherNested, found := other.Properties[prop]
			if !found || !nested.Equal(otherNested) {
				return false
			}
		}
		if s.AdditionalProperties != nil && other.AdditionalProperties != nil &&
			!s.AdditionalProperties.Equal(other.AdditionalProperties) {
			return false
		}
		if s.AdditionalProperties != nil && other.AdditionalProperties == nil ||
			s.AdditionalProperties == nil && other.AdditionalProperties != nil {
			return false
		}
		return true
	case ListType:
		return s.Items.Equal(other.Items)
	default:
		return true
	}
}

// FindProperty returns the Open API Schema type for the given property name.
//
// A property may either be explicitly defined in a `properties` map or implicitly defined in an
// `additionalProperties` block.
func (s *OpenAPISchema) FindProperty(name string) (*OpenAPISchema, bool) {
	if s.ModelType() == "any" {
		return s, true
	}
	if s.Properties != nil {
		prop, found := s.Properties[name]
		if found {
			return prop, true
		}
	}
	if s.AdditionalProperties != nil {
		return s.AdditionalProperties, true
	}
	return nil, false
}

var (
	// SchemaDef defines an Open API Schema definition in terms of an Open API Schema.
	SchemaDef *OpenAPISchema

	// InstanceSchema defines a basic schema for defining Policy Instances where the instance rule
	// references a TemplateSchema derived from the Instance's template kind.
	InstanceSchema *OpenAPISchema

	// TemplateSchema defines a schema for defining Policy Templates.
	TemplateSchema *OpenAPISchema

	openAPISchemaTypes map[string]string = map[string]string{
		"boolean": BoolType,
		"number":  DoubleType,
		"integer": IntType,
		"null":    NullType,
		"string":  StringType,
		"date":    TimestampType,
		"array":   ListType,
		"object":  MapType,
		"":        "any",
	}
)

const (
	schemaDefYaml = `
type: object
properties:
  type:
    type: string
  format:
    type: string
  description:
    type: string
  required:
    type: array
    items:
      type: string
  enum:
    type: array
    items:
      type: string
  default: {}
  items:
    $ref: "#openAPISchema"
  properties:
    type: object
    additionalProperties:
      $ref: "#openAPISchema"
  additionalProperties:
    $ref: "#openAPISchema"
  metadata:
    type: object
    additionalProperties:
      type: string
`

	templateSchemaYaml = `
type: object
required:
  - apiVersion
  - kind
  - metadata
  - evaluator
properties:
  apiVersion:
    type: string
  kind:
    type: string
  metadata:
    type: object
    required:
      - name
    properties:
      uid:
        type: string
      name:
        type: string
      namespace:
        type: string
        default: "default"
    additionalProperties:
      type: string
  description:
    type: string
  schema:
    $ref: "#openAPISchema"
  validator:
    type: object
    required:
      - productions
    properties:
      environment:
        type: string
      terms:
        type: object
        additionalProperties: {}
      productions:
        type: array
        items:
          type: object
          required:
            - message
          properties:
            match:
              type: string
              default: true
            message:
              type: string
            details: {}
  evaluator:
    type: object
    required:
      - productions
    properties:
      environment:
        type: string
      terms:
        type: object
        additionalProperties:
          type: string
      productions:
        type: array
        items:
          type: object
          properties:
            match:
              type: string
              default: "true"
            decision:
              type: string
            decisionRef:
              type: string
            output: {}
            decisions:
              type: array
              items:
                type: object
                required:
                  - output
                properties:
                  decision:
                    type: string
                  decisionRef:
                    type: string
                  output: {}
`

	instanceSchemaYaml = `
type: object
required:
  - apiVersion
  - kind
  - metadata
properties:
  apiVersion:
    type: string
  kind:
    type: string
  metadata:
    type: object
    additionalProperties:
      type: string
  description:
    type: string
  selector:
    type: object
    properties:
      matchLabels:
        type: object
        additionalProperties:
          type: string
      matchExpressions:
        type: array
        items:
          type: object
          required:
            - key
            - operator
          properties:
            key:
              type: string
            operator:
              type: string
              enum: ["Exists", "In", "NotIn"]
            values:
              type: array
              items: {}
              default: []
  rule:
    $ref: "#templateRuleSchema"
  rules:
    type: array
    items:
      $ref: "#templateRuleSchema"
`
)

func init() {
	InstanceSchema = NewOpenAPISchema()
	in := strings.ReplaceAll(instanceSchemaYaml, "\t", "  ")
	err := yaml.Unmarshal([]byte(in), InstanceSchema)
	if err != nil {
		panic(err)
	}
	SchemaDef = NewOpenAPISchema()
	in = strings.ReplaceAll(schemaDefYaml, "\t", "  ")
	err = yaml.Unmarshal([]byte(in), SchemaDef)
	if err != nil {
		panic(err)
	}
	TemplateSchema = NewOpenAPISchema()
	in = strings.ReplaceAll(templateSchemaYaml, "\t", "  ")
	err = yaml.Unmarshal([]byte(in), TemplateSchema)
	if err != nil {
		panic(err)
	}
}
