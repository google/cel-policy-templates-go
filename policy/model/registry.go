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
	"fmt"

	"github.com/google/cel-go/cel"
)

type Resolver interface {
	FindEnv(name string) (*Env, bool)
	FindExprEnv(name string) (*cel.Env, bool)
	FindSchema(name string) (*OpenAPISchema, bool)
	FindTemplate(name string) (*Template, bool)
	FindType(name string) (*DeclType, bool)
}

func NewRegistry(stdExprEnv *cel.Env) *Registry {
	return &Registry{
		envs:     map[string]*Env{},
		exprEnvs: map[string]*cel.Env{"": stdExprEnv},
		schemas: map[string]*OpenAPISchema{
			"#anySchema":      AnySchema,
			"#declTypeSchema": declTypeSchema,
			"#envSchema":      envSchema,
			"#instanceSchema": instanceSchema,
			"#openAPISchema":  schemaDef,
			"#templateSchema": templateSchema,
		},
		templates: map[string]*Template{},
		types: map[string]*DeclType{
			AnyType.TypeName():       AnyType,
			BoolType.TypeName():      BoolType,
			BytesType.TypeName():     BytesType,
			DoubleType.TypeName():    DoubleType,
			DurationType.TypeName():  DurationType,
			IntType.TypeName():       IntType,
			NullType.TypeName():      NullType,
			PlainTextType.TypeName(): PlainTextType,
			StringType.TypeName():    StringType,
			TimestampType.TypeName(): TimestampType,
			UintType.TypeName():      UintType,
			ListType.TypeName():      ListType,
			MapType.TypeName():       MapType,
		},
	}
}

// Registry defines a repository of environment, schema, template, and type definitions.
type Registry struct {
	envs      map[string]*Env
	exprEnvs  map[string]*cel.Env
	schemas   map[string]*OpenAPISchema
	templates map[string]*Template
	types     map[string]*DeclType
}

func (r *Registry) FindEnv(name string) (*Env, bool) {
	env, found := r.envs[name]
	return env, found
}

func (r *Registry) FindExprEnv(name string) (*cel.Env, bool) {
	exprEnv, found := r.exprEnvs[name]
	return exprEnv, found
}

func (r *Registry) FindSchema(name string) (*OpenAPISchema, bool) {
	schema, found := r.schemas[name]
	return schema, found
}

func (r *Registry) FindTemplate(name string) (*Template, bool) {
	tmpl, found := r.templates[name]
	return tmpl, found
}

func (r *Registry) FindType(name string) (*DeclType, bool) {
	typ, found := r.types[name]
	if found {
		return typ, true
	}
	return typ, found
}

func (r *Registry) SetEnv(name string, env *Env) error {
	// TODO: Cleanup environment related artifacts when the env is reset.
	baseExprEnv, found := r.FindExprEnv("")
	if !found {
		return fmt.Errorf("missing default expression environment")
	}
	exprEnv, err := baseExprEnv.Extend(env.ExprEnvOptions()...)
	if err != nil {
		return err
	}
	r.exprEnvs[name] = exprEnv
	r.envs[name] = env
	for typeName, typ := range env.Types {
		r.types[typeName] = typ
	}
	return nil
}

func (r *Registry) SetSchema(name string, schema *OpenAPISchema) error {
	r.schemas[name] = schema
	return nil
}

func (r *Registry) SetTemplate(name string, tmpl *Template) error {
	r.templates[name] = tmpl
	return nil
}

func (r *Registry) SetType(name string, declType *DeclType) error {
	r.types[name] = declType
	return nil
}
