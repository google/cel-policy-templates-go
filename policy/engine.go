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
	"sync"

	"github.com/google/cel-policy-templates-go/policy/compiler"
	"github.com/google/cel-policy-templates-go/policy/limits"
	"github.com/google/cel-policy-templates-go/policy/model"
	"github.com/google/cel-policy-templates-go/policy/parser"
	"github.com/google/cel-policy-templates-go/policy/runtime"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/interpreter"
)

// Engine evaluates context against policy instances to produce decisions.
type Engine struct {
	evalOpts  []cel.ProgramOption
	rtOpts    []runtime.TemplateOption
	selectors []Selector
	limits    *limits.Limits
	envs      map[string]*cel.Env
	schemas   map[string]*model.OpenAPISchema
	templates map[string]*model.Template
	instances map[string][]*model.Instance
	runtimes  map[string]*runtime.Template
	actPool   *activationPool
}

// NewEngine instantiates a policy.Engine with a set of configurable options.
//
// Custom functions and policy instance selectors must be provided as functional options to the
// engine construction if either is intended to be supported within the configured templates and
// instances.
func NewEngine(opts ...EngineOption) (*Engine, error) {
	e := &Engine{
		evalOpts:  []cel.ProgramOption{},
		rtOpts:    []runtime.TemplateOption{},
		selectors: []Selector{},
		limits:    limits.NewLimits(),
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
func (e *Engine) EvalAll(vars map[string]interface{}) ([]model.DecisionValue, error) {
	return e.evalInternal(vars, nil)
}

// Eval accepts an input context and produces a set of decisions as output.
//
// Which decisions are produced depends on the active set of policy instances and whether any rules
// within these policies apply to the context.
func (e *Engine) Eval(vars map[string]interface{},
	selector runtime.DecisionSelector) ([]model.DecisionValue, error) {
	return e.evalInternal(vars, selector)
}

// AddEnv configures the engine with a named reference to a CEL expression environment.
func (e *Engine) AddEnv(name string, exprEnv *cel.Env) {
	e.envs[name] = exprEnv
}

// AddInstance configures the engine with a given instance.
//
// Instances are grouped together by their 'kind' field which corresponds to a template
// metadata.name value.
func (e *Engine) AddInstance(inst *model.Instance) error {
	_, found := e.templates[inst.Kind]
	if !found {
		return fmt.Errorf(
			"template not found: instance=%s, template=%s",
			inst.Kind, inst.Metadata.Name)
	}
	insts, found := e.instances[inst.Kind]
	if !found {
		insts = []*model.Instance{}
	}
	insts = append(insts, inst)
	e.instances[inst.Kind] = insts
	return nil
}

// AddTemplate configures the engine with a given model.Template.
//
// The AddTemplate call will initialize an evaluable runtime.Template as a side-effect.
func (e *Engine) AddTemplate(tmpl *model.Template) error {
	e.templates[tmpl.Metadata.Name] = tmpl
	rtOpts := []runtime.TemplateOption{
		runtime.Limits(e.limits),
		runtime.ExprOptions(e.evalOpts...),
	}
	rtOpts = append(rtOpts, e.rtOpts...)
	rtTmpl, err := runtime.NewTemplate(e, tmpl, rtOpts...)
	if err != nil {
		return err
	}
	e.runtimes[tmpl.Metadata.Name] = rtTmpl
	return nil
}

// FindEnv returns the cel.Env associated with the given name, if found.
func (e *Engine) FindEnv(name string) (*cel.Env, bool) {
	env, found := e.envs[name]
	return env, found
}

// FindSchema returns the model.OpenAPISchema instance by its name, if present.
func (e *Engine) FindSchema(name string) (*model.OpenAPISchema, bool) {
	schema, found := e.schemas[name]
	return schema, found
}

// FindTemplate returns the model.Template object by its metadata.name field, if found.
func (e *Engine) FindTemplate(name string) (*model.Template, bool) {
	tmpl, found := e.templates[name]
	return tmpl, found
}

// CompileInstance parses, compiles, and validates an input source into a model.Instance.
// Note, the template referenced in the model.Instance 'kind' field must be configured within
// the engine before its instances can be compiled.
func (e *Engine) CompileInstance(src *model.Source) (*model.Instance, *Issues) {
	ast, iss := parser.ParseYaml(src)
	if iss.Err() != nil {
		return nil, iss
	}
	c := compiler.NewCompiler(e, e.limits, e.evalOpts...)
	return c.CompileInstance(src, ast)
}

// CompileTemplate parses and compiles an input source into a model.Template.
func (e *Engine) CompileTemplate(src *model.Source) (*model.Template, *Issues) {
	ast, iss := parser.ParseYaml(src)
	if iss.Err() != nil {
		return nil, iss
	}
	c := compiler.NewCompiler(e, e.limits, e.evalOpts...)
	return c.CompileTemplate(src, ast)
}

func (e *Engine) evalInternal(vars map[string]interface{},
	selector runtime.DecisionSelector) ([]model.DecisionValue, error) {
	input := e.actPool.Get().(*activation)
	defer e.actPool.Put(input)
	input.vars = vars
	var decisions []model.DecisionValue
	for tmplName, insts := range e.instances {
		rt, found := e.runtimes[tmplName]
		if !found {
			// Report an error
			continue
		}
		for _, inst := range insts {
			if !e.selectInstance(inst, input) {
				continue
			}
			decs, err := rt.Eval(inst, input, selector)
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

// DecisionNames filters the decision set which can be produced by the engine to a specific set
// of named decisions.
func DecisionNames(selected ...string) runtime.DecisionSelector {
	return func(decision string) bool {
		for _, s := range selected {
			if s == decision {
				return true
			}
		}
		return false
	}
}

// UnfinalizedDecisions filters the decisions down to the set of decisions which has not yet
// been finalized.
//
// Note, it is up to the caller to determine whether the policy instances have been completely
// evaluated as it is possible to shard the instances into different Engine instances and use
// the output of one evaluation as a filter into the next shard.
func UnfinalizedDecisions(values []model.DecisionValue) runtime.DecisionSelector {
	return func(decision string) bool {
		for _, v := range values {
			if v.Name() == decision {
				return !v.IsFinal()
			}
		}
		return true
	}
}

// Issues alias for simplifying the top-level interface of the engine.
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
