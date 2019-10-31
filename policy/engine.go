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

// Package policy includes objects used to define, instantiate, and enforce policies.
package policy

import (
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter"
	"github.com/google/cel-go/interpreter/functions"
)

// Engine evaluates context against policy instances to produce decisions.
type Engine struct {
	files      map[fileType][]*file
	env        cel.Env
	evalOpts   []cel.ProgramOption
	evaluators map[string]*evaluator
	instances  []*instance
	templates  map[string]*template
}

// NewEngine instantiates a policy.Engine using an environment and a set of options.
func NewEngine(env cel.Env, opts ...EngineOption) (*Engine, error) {
	e := &Engine{
		files:      map[fileType][]*file{},
		env:        env,
		evalOpts:   []cel.ProgramOption{},
		evaluators: map[string]*evaluator{},
		instances:  []*instance{},
		templates:  map[string]*template{},
	}

	var err error
	for _, opt := range opts {
		e, err = opt(e)
		if err != nil {
			return nil, err
		}
	}

	baseTypes := types.NewRegistry()
	for _, src := range e.files[TemplateFile] {
		tmplModel, err := unmarshalTemplateModel(src)
		if err != nil {
			return nil, err
		}
		tmpl, err := tmplModel.bind(baseTypes)
		if err != nil {
			return nil, err
		}
		e.templates[tmpl.name] = tmpl
	}

	for _, src := range e.files[InstanceFile] {
		instModel, err := unmarshalInstanceModel(src)
		if err != nil {
			return nil, err
		}
		tmpl, found := e.templates[instModel.templateName()]
		if !found {
			return nil, fmt.Errorf("no such template: %s", instModel.templateName())
		}
		inst, err := instModel.bind(tmpl)
		if err != nil {
			return nil, err
		}
		e.instances = append(e.instances, inst)
	}

	for _, src := range e.files[EvaluatorFile] {
		evalModel, err := unmarshalEvaluatorModel(src)
		if err != nil {
			return nil, err
		}
		tmpl, found := e.templates[evalModel.templateName()]
		if !found {
			return nil, fmt.Errorf("no such template: %s", evalModel.templateName())
		}
		tmplEnv, err := env.Extend(
			cel.Declarations(
				decls.NewIdent("spec", decls.NewObjectType(tmpl.name), nil)),
			cel.CustomTypeProvider(tmpl),
		)
		if err != nil {
			return nil, err
		}
		eval, err := evalModel.bind(tmplEnv, e.evalOpts...)
		if err != nil {
			return nil, err
		}
		e.evaluators[evalModel.templateName()] = eval
	}
	return e, nil
}

// Evaluate accepts an input context and produces a set of decisions as output.
//
// Which decisions are produced depends on the active set of policy instances and whether any rules
// within these policies apply to the context.
func (e *Engine) Evaluate(ctx map[string]interface{}) ([]ref.Val, error) {
	input, _ := interpreter.NewActivation(ctx)
	var decisions []ref.Val
	for _, inst := range e.instances {
		spec, _ := interpreter.NewActivation(
			map[string]interface{}{"spec": inst})
		data := interpreter.NewHierarchicalActivation(spec, input)
		eval := e.evaluators[inst.templateName()]
		decs, err := eval.Eval(data)
		if err != nil {
			return nil, err
		}
		decisions = append(decisions, decs...)
	}
	return decisions, nil
}

// EngineOption is a functional option for configuring the policy engine.
type EngineOption func(*Engine) (*Engine, error)

// Functions provides custom function implementations for functions expected by policy evaluators.
func Functions(funcs ...*functions.Overload) EngineOption {
	return func(e *Engine) (*Engine, error) {
		if len(funcs) == 0 {
			return e, nil
		}
		e.evalOpts = append(e.evalOpts, cel.Functions(funcs...))
		return e, nil
	}
}

// SourceFile specifies a file type and location as part of the startup configuration for the
// engine.
//
// Source files are one of three types and read in the following order:
// - policy.TemplateFile for policy template definitions.
// - policy.InstanceFile for policy instances of a given policy template.
// - policy.EvaluatorFile for evaluator definitions which refer to a given template.
//
// Source files may be specified in any order to the NewEngine function.
func SourceFile(st fileType, location string) EngineOption {
	return func(e *Engine) (*Engine, error) {
		return e.addSourceFile(st, location)
	}
}

func (e *Engine) addSourceFile(ft fileType, loc string) (*Engine, error) {
	files, found := e.files[ft]
	if !found {
		files = []*file{}
	}
	f, err := readFile(loc)
	if err != nil {
		return nil, err
	}
	e.files[ft] = append(files, f)
	return e, nil
}
