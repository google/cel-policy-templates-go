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
	"gopkg.in/yaml.v3"
)

type OpenAPISchema struct {
	Type                 string                    `yaml:"type"`
	Format               string                    `yaml:"format,omitempty"`
	Items                *OpenAPISchema            `yaml:"items,omitempty"`
	Enums                []string                  `yaml:"enums,omitempty"`
	Required             bool                      `yaml:"required,omitempty"`
	Properties           map[string]*OpenAPISchema `yaml:"properties,omitempty"`
	AdditionalProperties *OpenAPISchema            `yaml:"additionalProperties,omitempty"`
}

var (
	InstanceSchema *OpenAPISchema
)

const (
	instanceSchemaYaml = `
type: object
properties:
  version:
    type: string
    required: true
  kind:
    type: string
    required: true
  metadata:
    type: object
    required: true
    properties:
      name:
        type: string
        required: true
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
          properties:
            key:
              type: string
              required: true
            operator:
              type: string
              enums: ["Exists", "In", "NotIn"]
              required: true
            values:
              type: array
              items:
                type: string
  rules:
    type: array
    items:
      type: dyn
`
)

func init() {
	InstanceSchema = &OpenAPISchema{}
	err := yaml.Unmarshal([]byte(instanceSchemaYaml), InstanceSchema)
	if err != nil {
		panic(err)
	}
}
