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
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"

	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

func NewEnv(name string) *Env {
	return &Env{
		Name:      name,
		Functions: []*Function{},
		Vars:      []*Var{},
		Types:     map[string]*DeclType{},
	}
}

type Env struct {
	Name      string
	Container string
	Functions []*Function
	Vars      []*Var
	Types     map[string]*DeclType
}

func (e *Env) ExprEnvOptions() []cel.EnvOption {
	opts := []cel.EnvOption{}
	if e.Container != "" {
		opts = append(opts, cel.Container(e.Container))
	}
	if len(e.Vars) > 0 {
		vars := make([]*exprpb.Decl, len(e.Vars))
		for i, v := range e.Vars {
			vars[i] = v.exprDecl()
		}
		opts = append(opts, cel.Declarations(vars...))
	}
	if len(e.Functions) > 0 {
		funcs := make([]*exprpb.Decl, len(e.Functions))
		for i, f := range e.Functions {
			funcs[i] = f.exprDecl()
		}
		opts = append(opts, cel.Declarations(funcs...))
	}
	return opts
}

func NewVar(name string, dt *DeclType) *Var {
	return &Var{
		Name: name,
		Type: dt,
	}
}

type Var struct {
	Name string
	Type *DeclType
}

func (v *Var) exprDecl() *exprpb.Decl {
	return decls.NewVar(v.Name, v.Type.ExprType())
}

func NewFunction(name string, overloads ...*Overload) *Function {
	return &Function{
		Name:      name,
		Overloads: overloads,
	}
}

type Function struct {
	Name      string
	Overloads []*Overload
}

func (f *Function) exprDecl() *exprpb.Decl {
	overloadDecls := make([]*exprpb.Decl_FunctionDecl_Overload, len(f.Overloads))
	for i, o := range f.Overloads {
		overloadDecls[i] = o.overloadDecl()
	}
	return decls.NewFunction(f.Name, overloadDecls...)
}

// NewOverload returns an overload declaration for a given function.
//
// The overload name must follow the conventions laid out within the CEL overloads.go file.
//
//     // Receiver style function overload:
//     <receiver_type>_<func>_<arg_type0>_<arg_typeN>
//     // Namespaced style function overload:
//     <func>_<arg_type0>_<arg_typeN>
//
// Within this function, the last type supplied to the call is used as the return type. At least
// one type must be specified for a zero-arity function.
func NewOverload(name string, first *DeclType, rest ...*DeclType) *Overload {
	argTypes := make([]*DeclType, 1+len(rest))
	argTypes[0] = first
	for i := 1; i < len(rest)+1; i++ {
		argTypes[i] = rest[i-1]
	}
	returnType := argTypes[len(argTypes)-1]
	argTypes = argTypes[0 : len(argTypes)-2]
	return newOverload(name, false, argTypes, returnType)
}

func NewNamespacedOverload(name string, first *DeclType, rest ...*DeclType) *Overload {
	argTypes := make([]*DeclType, 1+len(rest))
	argTypes[0] = first
	for i := 1; i < len(rest)+1; i++ {
		argTypes[i] = rest[i-1]
	}
	returnType := argTypes[len(argTypes)-1]
	argTypes = argTypes[0 : len(argTypes)-2]
	return newOverload(name, true, argTypes, returnType)
}

func newOverload(name string,
	namespaced bool,
	argTypes []*DeclType,
	returnType *DeclType) *Overload {
	return &Overload{
		Name:       name,
		Namespaced: namespaced,
		Args:       argTypes,
		ReturnType: returnType,
	}
}

type Overload struct {
	Name       string
	Namespaced bool
	Args       []*DeclType
	ReturnType *DeclType
}

func (o *Overload) overloadDecl() *exprpb.Decl_FunctionDecl_Overload {
	typeParams := []string{}
	argExprTypes := make([]*exprpb.Type, len(o.Args))
	for i, a := range o.Args {
		if a.TypeParam {
			typeParams = append(typeParams, a.TypeName())
		}
		argExprTypes[i] = a.ExprType()
	}
	returnType := o.ReturnType.ExprType()
	if len(typeParams) == 0 {
		if o.Namespaced {
			return decls.NewOverload(o.Name, argExprTypes, returnType)
		}
		return decls.NewInstanceOverload(o.Name, argExprTypes, returnType)
	}
	if o.Namespaced {
		return decls.NewParameterizedOverload(o.Name, argExprTypes, returnType, typeParams)
	}
	return decls.NewParameterizedInstanceOverload(o.Name, argExprTypes, returnType, typeParams)
}
