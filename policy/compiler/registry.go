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

package compiler

import (
	"github.com/google/cel-go/cel"

	"github.com/google/cel-policy-templates-go/policy/model"
)

// Registry defines an interface for looking up schema and environment references during source
// compilation.
type Registry interface {
	FindSchema(name string) (*model.OpenAPISchema, bool)

	RegisterSchema(name string, s *model.OpenAPISchema) error

	FindEnv(name string) (*cel.Env, bool)

	RegisterEnv(name string, env *cel.Env) error

	FindTemplate(name string) (*model.Template, bool)

	RegisterTemplate(name string, tmpl *model.Template) error
}
