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
	"sync"

	"github.com/google/cel-policy-templates-go/policy/compiler"
	"github.com/google/cel-policy-templates-go/policy/model"
	"github.com/google/cel-policy-templates-go/policy/parser"
	"github.com/google/cel-policy-templates-go/policy/runtime"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/interpreter"
	"github.com/google/cel-go/interpreter/functions"
)

// Engine evaluates context against policy instances to produce decisions.
type Engine struct {
	evalOpts  []cel.ProgramOption
	selectors []Selector
	envs      map[string]*cel.Env
	schemas   map[string]*model.OpenAPISchema
	templates map[string]*model.Template
	instances map[string][]*model.Instance
	runtimes  map[string]*runtime.Template
	actPool   *activationPool
}

// NewEngine instantiates a policy.Engine using an environment and a set of options.
func NewEngine(opts ...EngineOption) (*Engine, error) {
	e := &Engine{
		evalOpts:  []cel.ProgramOption{},
		selectors: []Selector{},
		envs: map[string]*cel.Env{
			"": stdEnv,
		},
		schemas: map[string]*model.OpenAPISchema{
			"#openAPISchema":  model.SchemaDef,
			"#instanceSchema": model.InstanceSchema,
			"#templateSchema": model.TemplateSchema,
		},
		templates: map[string]*model.Template{},
		instances: map[string][]*model.Instance{},
		runtimes:  map[string]*runtime.Template{},
		actPool:   newActivationPool(),
	}
	var err error
	for _, opt := range opts {
		e, err = opt(e)
		if err != nil {
			return nil, err
		}
	}
	return e, nil
}

// Eval accepts an input context and produces a set of decisions as output.
//
// Which decisions are produced depends on the active set of policy instances and whether any rules
// within these policies apply to the context.
func (e *Engine) Eval(ctx map[string]interface{}) ([]*model.DecisionValue, error) {
	input := e.actPool.Get().(*activation)
	defer e.actPool.Put(input)
	input.vars = ctx
	var decisions []*model.DecisionValue
	for tmplName, insts := range e.instances {
		rt, found := e.runtimes[tmplName]
		if !found {
			continue
		}
		for _, inst := range insts {
			if !e.selectInstance(inst, input) {
				continue
			}
			decs, err := rt.Eval(inst, input)
			if err != nil {
				return nil, err
			}
			decisions = append(decisions, decs...)
		}
	}
	return decisions, nil
}

func (e *Engine) selectInstance(inst *model.Instance, input interpreter.Activation) bool {
	if len(inst.Selectors) == 0 || len(e.selectors) == 0 {
		return true
	}
	for _, selFn := range e.selectors {
		for _, sel := range inst.Selectors {
			if selFn(sel, input) {
				return true
			}
		}
	}
	return false
}

func (e *Engine) AddEnv(name string, exprEnv *cel.Env) {
	e.envs[name] = exprEnv
}

func (e *Engine) AddInstance(inst *model.Instance) {
	insts, found := e.instances[inst.Kind]
	if !found {
		insts = []*model.Instance{}
	}
	insts = append(insts, inst)
	e.instances[inst.Kind] = insts
}

func (e *Engine) AddTemplate(tmpl *model.Template) error {
	e.templates[tmpl.Metadata.Name] = tmpl
	rtTmpl, err := runtime.NewTemplate(e, tmpl, e.evalOpts...)
	if err != nil {
		return err
	}
	e.runtimes[tmpl.Metadata.Name] = rtTmpl
	return nil
}

func (e *Engine) FindEnv(name string) (*cel.Env, bool) {
	env, found := e.envs[name]
	return env, found
}

func (e *Engine) FindSchema(name string) (*model.OpenAPISchema, bool) {
	schema, found := e.schemas[name]
	return schema, found
}

func (e *Engine) FindTemplate(name string) (*model.Template, bool) {
	tmpl, found := e.templates[name]
	return tmpl, found
}

func (e *Engine) RemoveInstance(name, uid string) {

}

func (e *Engine) RemoveTemplate(name string) {
	delete(e.templates, name)
}

func (e *Engine) CompileInstance(src *model.Source) (*model.Instance, *Issues) {
	ast, iss := parser.ParseYaml(src)
	if iss.Err() != nil {
		return nil, iss
	}
	c := compiler.NewCompiler(e, e.evalOpts...)
	return c.CompileInstance(src, ast)
}

func (e *Engine) CompileTemplate(src *model.Source) (*model.Template, *Issues) {
	ast, iss := parser.ParseYaml(src)
	if iss.Err() != nil {
		return nil, iss
	}
	c := compiler.NewCompiler(e)
	return c.CompileTemplate(src, ast)
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

type Selector func(model.Selector, interpreter.Activation) bool

func Selectors(selectors ...Selector) EngineOption {
	return func(e *Engine) (*Engine, error) {
		e.selectors = selectors
		return e, nil
	}
}

type Issues = cel.Issues

func newActivationPool() *activationPool {
	return &activationPool{
		Pool: &sync.Pool{
			New: func() interface{} {
				return &activation{}
			},
		},
	}
}

type activationPool struct {
	*sync.Pool
}

type activation struct {
	vars map[string]interface{}
}

func (a *activation) Parent() interpreter.Activation {
	return nil
}

func (a *activation) ResolveName(name string) (interface{}, bool) {
	val, found := a.vars[name]
	return val, found
}

var stdEnv *cel.Env

func init() {
	stdEnv, _ = cel.NewEnv()
}
