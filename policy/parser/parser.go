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

// Package parser defines the primary interfaces for parsing different data formats which
// can be represented within the CPT policy model.
package parser

import (
	"github.com/google/cel-go/cel"

	"github.com/google/cel-policy-templates-go/policy/model"
	"github.com/google/cel-policy-templates-go/policy/parser/yml"
)

// ParseYaml decodes a YAML source to a model.ParsedValue.
//
// If errors are encountered during decode, they are returned via the Errors object.
func ParseYaml(src *model.Source) (*model.ParsedValue, *cel.Issues) {
	return yml.Parse(src)
}
