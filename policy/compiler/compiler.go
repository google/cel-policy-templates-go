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

// Package compiler contains a suite of tools for covering parsed representations of CEL Policy
// Template sources into type-checked and validated in-memory representations.
package compiler

import (
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/cel-policy-templates-go/policy/limits"
	"github.com/google/cel-policy-templates-go/policy/model"
	"github.com/google/cel-policy-templates-go/policy/runtime"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common"
	"github.com/google/cel-go/common/types"

	"google.golang.org/protobuf/proto"

	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

// NewCompiler creates a new Compiler instance with the given Registry and CEL evaluation options.
func NewCompiler(reg *model.Registry, l *limits.Limits, rtOpts ...runtime.TemplateOption) *Compiler {
	return &Compiler{
		rtOpts: rtOpts,
		reg:    reg,
		limits: l,
	}
}

// Compiler type-checks and compiles a raw model.ParsedValue into a strongly typed in-memory
// representation of a template or policy instance.
type Compiler struct {
	rtOpts []runtime.TemplateOption
	reg    *model.Registry
	limits *limits.Limits
}

// CompileEnv type-checks and builds model.Env instance from a parsed representation.
//
// The resulting model.Env value may be used to extend a base CEL environment with additional
// variable, function, and type declarations.
func (c *Compiler) CompileEnv(src *model.Source, parsedEnv *model.ParsedValue) (*model.Env, *cel.Issues) {
	envComp, iss := c.newEnvCompiler(src, parsedEnv)
	if iss.Err() != nil {
		return nil, iss
	}
	return envComp.compile()
}

// CompileInstance type-checks and validates a parsed representation of a policy instance whose
// format and validation logic is also determined by policy template referenced in the policy
// instance 'kind' field.
func (c *Compiler) CompileInstance(src *model.Source, parsedInst *model.ParsedValue) (*model.Instance, *cel.Issues) {
	ic, iss := c.newInstanceCompiler(src, parsedInst)
	if iss.Err() != nil {
		return nil, iss
	}
	if len(ic.errors.GetErrors()) > 0 {
		return nil, cel.NewIssues(ic.errors)
	}
	return ic.compile()
}

// CompileTemplate type-checks and validates a parsed representation of a policy template.
func (c *Compiler) CompileTemplate(src *model.Source, parsedTmpl *model.ParsedValue) (*model.Template, *cel.Issues) {
	tmplComp, iss := c.newTemplateCompiler(src, parsedTmpl)
	if iss.Err() != nil {
		return nil, iss
	}
	return tmplComp.compile()
}

// CompileSchema validates a parsed representation of a type schema and produces an OpenAPISchema as output.
func (c *Compiler) CompileSchema(src *model.Source, parsedSchema *model.ParsedValue) (*model.OpenAPISchema, *cel.Issues) {
	dc := c.newDynCompiler(src, parsedSchema)
	dyn, err := model.NewDynValue(parsedSchema.ID, parsedSchema.Value)
	if err != nil {
		dc.reportError(err.Error())
		return nil, cel.NewIssues(dc.errors)
	}
	schema := model.NewOpenAPISchema()
	dc.compileOpenAPISchema(dyn, schema, false)
	errs := dc.errors.GetErrors()
	if len(errs) > 0 {
		return nil, cel.NewIssues(dc.errors)
	}
	return schema, nil
}

func (c *Compiler) newEnvCompiler(src *model.Source, parsedEnv *model.ParsedValue) (*envCompiler, *cel.Issues) {
	dc := c.newDynCompiler(src, parsedEnv)
	dyn, err := model.NewDynValue(parsedEnv.ID, parsedEnv.Value)
	if err != nil {
		dc.reportError(err.Error())
		return nil, cel.NewIssues(dc.errors)
	}
	envSchema, _ := c.reg.FindSchema("#envSchema")
	dc.checkSchema(dyn, envSchema)
	return &envCompiler{
		dynCompiler: dc,
		dyn:         dyn,
	}, nil
}

func (c *Compiler) newInstanceCompiler(src *model.Source, parsedInst *model.ParsedValue) (*instanceCompiler, *cel.Issues) {
	dc := c.newDynCompiler(src, parsedInst)
	dyn, err := model.NewDynValue(parsedInst.ID, parsedInst.Value)
	if err != nil {
		dc.reportError(err.Error())
		return nil, cel.NewIssues(dc.errors)
	}
	tmplName := dc.mapFieldStringValueOrEmpty(dyn, "kind")
	tmpl, found := dc.reg.FindTemplate(tmplName)
	if !found {
		// report an error and return
		dc.reportError("no such template: %s", tmplName)
		return nil, cel.NewIssues(dc.errors)
	}
	if tmpl.RuleTypes != nil {
		dc.reg.ruleSchema = tmpl.RuleTypes.Schema
	}
	instSchema, _ := c.reg.FindSchema("#instanceSchema")
	dc.checkSchema(dyn, instSchema)
	return &instanceCompiler{
		dynCompiler: dc,
		dyn:         dyn,
		rt:          tmpl.RuleTypes,
		tmpl:        tmpl,
		rtOpts:      c.rtOpts,
	}, nil
}

func (c *Compiler) newTemplateCompiler(src *model.Source, parsedTmpl *model.ParsedValue) (*templateCompiler, *cel.Issues) {
	dc := c.newDynCompiler(src, parsedTmpl)
	dyn, err := model.NewDynValue(parsedTmpl.ID, parsedTmpl.Value)
	if err != nil {
		dc.reportError(err.Error())
		return nil, cel.NewIssues(dc.errors)
	}
	tmplSchema, _ := c.reg.FindSchema("#templateSchema")
	dc.checkSchema(dyn, tmplSchema)
	return &templateCompiler{
		dynCompiler: dc,
		dyn:         dyn,
	}, nil
}

func (c *Compiler) newDynCompiler(src *model.Source,
	pv *model.ParsedValue) *dynCompiler {
	return &dynCompiler{
		reg: &compReg{
			Registry: c.reg,
		},
		limits: c.limits,
		src:    src,
		meta:   pv.Meta,
		errors: common.NewErrors(src),
	}
}

type envCompiler struct {
	*dynCompiler
	dyn *model.DynValue
}

func (ec *envCompiler) compile() (*model.Env, *cel.Issues) {
	m := ec.mapValue(ec.dyn)
	name := ec.mapFieldStringValueOrEmpty(ec.dyn, "name")
	cenv := model.NewEnv(name)
	container := ec.mapFieldStringValueOrEmpty(ec.dyn, "container")
	cenv.Container = container
	vars, found := m.GetField("variables")
	if found {
		// Compile the variables
		varMap := ec.mapValue(vars.Ref)
		for _, f := range varMap.Fields {
			ec.compileVar(cenv, f.Name, f.Ref)
		}
	}
	funcs, found := m.GetField("functions")
	if found {
		// Compile the functions
		funcMap := ec.mapValue(funcs.Ref)
		ec.compileFunctions(cenv, funcMap)
	}
	errs := ec.errors.GetErrors()
	if len(errs) > 0 {
		return nil, cel.NewIssues(ec.errors)
	}
	return cenv, nil
}

func (ec *envCompiler) compileVar(env *model.Env, name string, dyn *model.DynValue) {
	varType := ec.compileDeclType(env, dyn)
	if varType.TypeParam {
		ec.reportErrorAtID(dyn.ID, "variable must not be type-param type")
	}

	v := model.NewVar(name, varType)
	env.Vars = append(env.Vars, v)
}

func (ec *envCompiler) compileFunctions(env *model.Env, funcMap *model.MapValue) {
	exts, found := funcMap.GetField("extensions")
	if !found {
		return
	}
	extMap := ec.mapValue(exts.Ref)
	for _, f := range extMap.Fields {
		overloadMap := ec.mapValue(f.Ref)
		overloads := make([]*model.Overload, 0, len(overloadMap.Fields))
		for _, o := range overloadMap.Fields {
			oName := o.Name
			obj := ec.mapValue(o.Ref)
			freeFunction := false
			ns, found := obj.GetField("free_function")
			if found {
				freeFunction = ec.boolValue(ns.Ref)
			}
			args, found := obj.GetField("args")
			argVals := []*model.DeclType{}
			if found {
				argList := ec.listValue(args.Ref)
				for _, a := range argList.Entries {
					argVal := ec.compileDeclType(env, a)
					argVals = append(argVals, argVal)
				}
			}
			ret, found := obj.GetField("return")
			if found {
				retType := ec.compileDeclType(env, ret.Ref)
				argVals = append(argVals, retType)
			}
			if freeFunction {
				if len(argVals) == 1 {
					overloads = append(overloads,
						model.NewFreeFunctionOverload(oName, argVals[0]))
				} else {
					overloads = append(overloads,
						model.NewFreeFunctionOverload(oName, argVals[0], argVals[1:]...))
				}
			} else {
				if len(argVals) == 1 {
					overloads = append(overloads, model.NewOverload(oName, argVals[0]))
				} else {
					overloads = append(overloads,
						model.NewOverload(oName, argVals[0], argVals[1:]...))
				}
			}
		}
		fn := model.NewFunction(f.Name, overloads...)
		env.Functions = append(env.Functions, fn)
	}
}

func (ec *envCompiler) compileDeclType(env *model.Env, dyn *model.DynValue) *model.DeclType {
	schema := model.NewOpenAPISchema()
	ec.compileOpenAPISchema(dyn, schema, true)
	dt := schema.DeclType()
	ec.collectTypes(env, dt)
	return dt
}

func (ec *envCompiler) collectTypes(env *model.Env, typ *model.DeclType) {
	if typ.IsObject() {
		name := typ.TypeName()
		if name != "" && name != "object" {
			env.Types[name] = typ
		}
		for _, f := range typ.Fields {
			ec.collectTypes(env, f.Type)
		}
	}
	if typ.IsMap() {
		ec.collectTypes(env, typ.KeyType)
		ec.collectTypes(env, typ.ElemType)
	}
	if typ.IsList() {
		ec.collectTypes(env, typ.ElemType)
	}
}

type instanceCompiler struct {
	*dynCompiler
	dyn    *model.DynValue
	rt     *model.RuleTypes
	tmpl   *model.Template
	rtOpts []runtime.TemplateOption
}

func (ic *instanceCompiler) compile() (*model.Instance, *cel.Issues) {
	cinst := model.NewInstance(ic.meta)
	cinst.APIVersion = ic.mapFieldStringValueOrEmpty(ic.dyn, "apiVersion")
	cinst.Description = ic.mapFieldStringValueOrEmpty(ic.dyn, "description")
	cinst.Kind = ic.mapFieldStringValueOrEmpty(ic.dyn, "kind")

	m := ic.mapValue(ic.dyn)
	meta, found := m.GetField("metadata")
	if found {
		ic.compileMetadata(meta.Ref, cinst.Metadata)
	}
	selector, found := m.GetField("selector")
	if found {
		ic.compileSelectors(selector.Ref, cinst)
	}
	rules, rsfound := m.GetField("rules")
	if rsfound {
		ruleSet := ic.listValue(rules.Ref)
		cinst.Rules = make([]model.Rule, len(ruleSet.Entries))
		for i, rule := range ruleSet.Entries {
			cinst.Rules[i] = ic.convertToRule(rule)
		}
	}
	rule, rfound := m.GetField("rule")
	if rfound {
		r := ic.convertToRule(rule.Ref)
		cinst.Rules = []model.Rule{r}
	}
	if rsfound && rfound {
		ic.reportErrorAtID(rules.ID,
			"only one of the fields may be set: [rule, rules]")
	}
	if ic.limits.RuleLimit >= 0 && len(cinst.Rules) > ic.limits.RuleLimit {
		reportID := cinst.Rules[ic.limits.RuleLimit].GetID()
		ic.reportErrorAtID(reportID,
			"rule limit set to %d, but %d found",
			ic.limits.RuleLimit, len(cinst.Rules))
	}
	rtOpts := append([]runtime.TemplateOption{runtime.Limits(ic.limits)}, ic.rtOpts...)
	exec, err := runtime.NewTemplate(
		ic.reg,
		ic.tmpl,
		rtOpts...)
	if err != nil {
		// report the error
		ic.reportError(err.Error())
	}
	iss := exec.Validate(ic.src, cinst)
	if iss != nil {
		ic.errors = ic.errors.Append(iss.Errors())
	}
	errs := ic.errors.GetErrors()
	if len(errs) > 0 {
		return nil, cel.NewIssues(ic.errors)
	}
	return cinst, nil
}

func (ic *instanceCompiler) convertToRule(dyn *model.DynValue) model.Rule {
	// TODO: handle CEL expression compilation, possibly as an observer
	return ic.rt.ConvertToRule(dyn)
}

func (ic *instanceCompiler) compileMetadata(dyn *model.DynValue,
	cmeta *model.InstanceMetadata) {
	cmeta.Name = ic.mapFieldStringValueOrEmpty(dyn, "name")
	cmeta.UID = ic.mapFieldStringValueOrEmpty(dyn, "uid")
	cmeta.Namespace = ic.mapFieldStringValueOrEmpty(dyn, "namespace")
}

func (ic *instanceCompiler) compileSelectors(dyn *model.DynValue,
	cinst *model.Instance) {
	selectors := ic.mapValue(dyn)
	for _, f := range selectors.Fields {
		switch f.Name {
		case "matchLabels":
			kvPairs := ic.mapValue(f.Ref)
			lblValues := make(map[string]string)
			for _, kvPair := range kvPairs.Fields {
				lblValues[kvPair.Name] = string(ic.strValue(kvPair.Ref))
			}
			sel := &model.LabelSelector{
				LabelValues: lblValues,
			}
			cinst.Selectors = append(cinst.Selectors, sel)
		case "matchExpressions":
			tuples := ic.listValue(f.Ref)
			for _, tuple := range tuples.Entries {
				k := ic.mapFieldStringValueOrEmpty(tuple, "key")
				op := ic.mapFieldStringValueOrEmpty(tuple, "operator")
				mv := ic.mapValue(tuple)
				valsField, found := mv.GetField("values")
				var vals []interface{}
				if found {
					valList := ic.listValue(valsField.Ref)
					for _, v := range valList.Entries {
						vals = append(vals, ic.convertToPrimitive(v))
					}
				}
				sel := &model.ExpressionSelector{
					Label:    k,
					Operator: op,
					Values:   vals,
				}
				cinst.Selectors = append(cinst.Selectors, sel)
			}
		}
	}
}

type templateCompiler struct {
	*dynCompiler
	dyn *model.DynValue
}

func (tc *templateCompiler) compile() (*model.Template, *cel.Issues) {
	ctmpl := model.NewTemplate(tc.meta)
	m := tc.mapValue(tc.dyn)
	ctmpl.APIVersion = tc.mapFieldStringValueOrEmpty(tc.dyn, "apiVersion")
	ctmpl.Description = tc.mapFieldStringValueOrEmpty(tc.dyn, "description")
	ctmpl.Kind = tc.mapFieldStringValueOrEmpty(tc.dyn, "kind")
	meta, found := m.GetField("metadata")
	if found {
		tc.compileMetadata(meta.Ref, ctmpl.Metadata)
	}
	schemaDef, found := m.GetField("schema")
	if found {
		schema := model.NewOpenAPISchema()
		tc.compileOpenAPISchema(schemaDef.Ref, schema, false)
		var err error
		ctmpl.RuleTypes, err = model.NewRuleTypes(
			ctmpl.Metadata.Name,
			schema,
			tc.reg)
		if err != nil {
			tc.reportError(err.Error())
		}
	}
	val, found := m.GetField("validator")
	if found {
		tc.compileValidator(val.Ref, ctmpl)
	}
	eval, found := m.GetField("evaluator")
	if found {
		tc.compileEvaluator(eval.Ref, ctmpl)
	}
	errs := tc.errors.GetErrors()
	if len(errs) > 0 {
		return nil, cel.NewIssues(tc.errors)
	}
	return ctmpl, nil
}

func (tc *templateCompiler) compileMetadata(dyn *model.DynValue, cmeta *model.TemplateMetadata) {
	m := tc.mapValue(dyn)
	cmeta.Name = tc.mapFieldStringValueOrEmpty(dyn, "name")
	cmeta.UID = tc.mapFieldStringValueOrEmpty(dyn, "uid")
	cmeta.Namespace = tc.mapFieldStringValueOrEmpty(dyn, "namespace")
	plural, found := m.GetField("pluralName")
	if found {
		cmeta.PluralName = string(tc.strValue(plural.Ref))
	} else {
		cmeta.PluralName = cmeta.Name + "s"
	}
}

func (tc *templateCompiler) compileValidator(dyn *model.DynValue, ctmpl *model.Template) {
	val := tc.mapValue(dyn)
	if len(val.Fields) == 0 {
		// TODO: maybe not intentional that the validator is empty.
		return
	}
	validator, productionsEnv := tc.buildProductionsEnv(dyn, ctmpl, tc.limits.ValidatorTermLimit)
	if validator == nil {
		// error occurred, will have been recorded elsewhere.
		return
	}
	prods, found := val.GetField("productions")
	if found {
		tc.compileValidatorOutputDecisions(prods.Ref, productionsEnv, validator, ctmpl)
	}
	ctmpl.Validator = validator
}

func (tc *templateCompiler) compileValidatorOutputDecisions(
	prods *model.DynValue, env *cel.Env, ceval *model.Evaluator, ctmpl *model.Template) {
	productions := tc.listValue(prods)
	if tc.limits.ValidatorProductionLimit >= 0 && len(productions.Entries) > tc.limits.ValidatorProductionLimit {
		reportID := productions.Entries[tc.limits.ValidatorProductionLimit].ID
		tc.reportErrorAtID(reportID,
			"validator production limit set to %d, but %d found",
			tc.limits.ValidatorProductionLimit, len(productions.Entries))
	}
	prodRules := make([]*model.Production, len(productions.Entries))
	for i, p := range productions.Entries {
		prod := tc.mapValue(p)
		match, _ := prod.GetField("match")
		matchAst := tc.compileExpr(match.Ref, env, true)
		if matchAst != nil && !proto.Equal(matchAst.ResultType(), decls.Bool) {
			tc.reportErrorAtID(match.Ref.ID,
				"expected bool match result, found: %s",
				checker.FormatCheckedType(matchAst.ResultType()))
		}
		rule := model.NewProduction(match.Ref.ID, matchAst)
		fieldTxt := tc.mapFieldStringValueOrEmpty(p, "field")
		if fieldTxt != "" {
			field, _ := prod.GetField("field")
			tc.validateValidatorField(fieldTxt, field.Ref.ID, ctmpl)
		}
		msg, found := prod.GetField("message")
		msgTxt := "''"
		if found {
			ast := tc.compileExpr(msg.Ref, env, false)
			if ast != nil {
				msgTxt, _ = cel.AstToString(ast)
			}
		}
		det, found := prod.GetField("details")
		detTxt := ""
		if found {
			ast := tc.compileExpr(det.Ref, env, false)
			if ast != nil {
				detTxt, _ = cel.AstToString(ast)
			}
		}
		// Note: this format will not yet work with structured outputs for the validator.
		var outb strings.Builder
		outb.WriteString(fmt.Sprintf("{'message': %s", msgTxt))
		if detTxt != "" {
			outb.WriteString(fmt.Sprintf(", 'details': %s", detTxt))
		}
		if fieldTxt != "" {
			outb.WriteString(fmt.Sprintf(", 'field': '%s'", fieldTxt))
		}
		outb.WriteString("}")
		outDyn, err := model.NewDynValue(p.ID, outb.String())
		if err != nil {
			tc.reportErrorAtID(p.ID, err.Error())
			continue
		}
		ast := tc.compileExpr(outDyn, env, true)
		outDec := model.NewDecision()
		outDec.Name = "policy.invalid"
		outDec.Output = ast
		rule.Decisions = append(rule.Decisions, outDec)
		prodRules[i] = rule
	}
	ceval.Productions = prodRules
}

func (tc *templateCompiler) validateValidatorField(fieldTxt string, reportID int64, ctmpl *model.Template) {
	fullPath := ctmpl.Metadata.Name + "." + fieldTxt
	lastIdx := strings.LastIndex(fullPath, ".")
	typeName, fieldName := fullPath[:lastIdx], fullPath[lastIdx+1:]
	_, found := ctmpl.RuleTypes.FindFieldType(typeName, fieldName)
	if !found {
		tc.reportErrorAtID(reportID, "invalid field")
	}
}

func (tc *templateCompiler) compileEvaluator(dyn *model.DynValue, ctmpl *model.Template) {
	eval := tc.mapValue(dyn)
	if len(eval.Fields) == 0 {
		return
	}
	evaluator, productionsEnv := tc.buildProductionsEnv(dyn, ctmpl, tc.limits.EvaluatorTermLimit)
	if evaluator == nil {
		// Error occurred, would have been reported elsewhere.
		return
	}
	prods, found := eval.GetField("productions")
	if found {
		tc.compileEvaluatorOutputDecisions(prods.Ref, productionsEnv, evaluator)
	} else {
		tc.reportErrorAtID(dyn.ID, "evaluator missing productions field")
	}
	ctmpl.Evaluator = evaluator
}

func (tc *templateCompiler) compileEvaluatorOutputDecisions(
	prods *model.DynValue, env *cel.Env, ceval *model.Evaluator) {
	productions := tc.listValue(prods)
	if tc.limits.EvaluatorProductionLimit >= 0 && len(productions.Entries) > tc.limits.EvaluatorProductionLimit {
		reportID := productions.Entries[tc.limits.EvaluatorProductionLimit].ID
		tc.reportErrorAtID(reportID,
			"evaluator production limit set to %d, but %d found",
			tc.limits.EvaluatorProductionLimit, len(productions.Entries))
	}
	prodRules := make([]*model.Production, len(productions.Entries))
	for i, p := range productions.Entries {
		prod := tc.mapValue(p)
		match, _ := prod.GetField("match")
		matchAst := tc.compileExpr(match.Ref, env, true)
		if matchAst != nil && !proto.Equal(matchAst.ResultType(), decls.Bool) {
			tc.reportErrorAtID(match.Ref.ID,
				"expected bool match result, found: %s",
				checker.FormatCheckedType(matchAst.ResultType()))
		}
		rule := model.NewProduction(match.Ref.ID, matchAst)
		outDec, decFound := tc.compileOutputDecision(p, env)
		if decFound && outDec != nil {
			rule.Decisions = append(rule.Decisions, outDec)
		}
		decs, decsFound := prod.GetField("decisions")
		if decFound && decsFound {
			tc.reportErrorAtID(decs.ID,
				"only one of the fields may be set: [decision, decisions]")
		}
		if decsFound {
			decsList := tc.listValue(decs.Ref)
			if tc.limits.EvaluatorDecisionLimit >= 0 && len(decsList.Entries) > tc.limits.EvaluatorDecisionLimit {
				reportID := decsList.Entries[tc.limits.EvaluatorDecisionLimit].ID
				tc.reportErrorAtID(reportID,
					"evaluator decision limit set to %d, but %d found",
					tc.limits.EvaluatorDecisionLimit, len(decsList.Entries))
			}
			for _, elem := range decsList.Entries {
				outDec, found := tc.compileOutputDecision(elem, env)
				if found && outDec != nil {
					rule.Decisions = append(rule.Decisions, outDec)
				}
			}
		}
		prodRules[i] = rule
	}
	ceval.Productions = prodRules
}

func (tc *templateCompiler) compileOutputDecision(
	dyn *model.DynValue,
	env *cel.Env) (*model.Decision, bool) {
	prod := tc.mapValue(dyn)
	dec, decFound := prod.GetField("decision")
	ref, refFound := prod.GetField("reference")
	out, outFound := prod.GetField("output")
	if !decFound && !refFound && !outFound {
		return nil, false
	}
	outDec := model.NewDecision()
	if decFound {
		decName := tc.strValue(dec.Ref)
		outDec.Name = string(decName)
	}
	if refFound {
		if decFound {
			tc.reportErrorAtID(dyn.ID,
				"only one of 'decision' or 'reference' may be specified.")
		}
		outDec.Reference = tc.compileExpr(ref.Ref, env, true)
	}
	if !decFound && !refFound {
		tc.reportErrorAtID(dyn.ID,
			"one of 'decision' or 'reference' must be specified")
	}
	if outFound {
		outDec.Output = tc.compileExpr(out.Ref, env, false)
	}
	// otherwise, output is not specified and should result in an error from schema checking.
	return outDec, true
}

func (tc *templateCompiler) buildProductionsEnv(dyn *model.DynValue,
	ctmpl *model.Template, termLimit int) (*model.Evaluator, *cel.Env) {
	eval := tc.mapValue(dyn)
	evaluator := model.NewEvaluator()
	evaluator.Environment = tc.mapFieldStringValueOrEmpty(dyn, "environment")
	env, err := tc.newEnv(evaluator.Environment, ctmpl)
	if err != nil {
		// report any environment creation errors.
		envName, _ := eval.GetField("environment")
		tc.reportErrorAtID(envName.Ref.ID, err.Error())
		return nil, nil
	}
	ranges, found := eval.GetField("ranges")
	productionsEnv := env
	if found {
		productionsEnv, err = tc.compileRanges(ranges.Ref, env, evaluator)
		if err != nil {
			tc.reportErrorAtID(ranges.Ref.ID, err.Error())
			return nil, nil
		}
	}
	terms, found := eval.GetField("terms")
	if found {
		productionsEnv, err = tc.compileTerms(terms.Ref, productionsEnv, evaluator, termLimit)
		if err != nil {
			tc.reportErrorAtID(terms.Ref.ID, err.Error())
			return nil, nil
		}
	}
	return evaluator, productionsEnv
}

func (tc *templateCompiler) compileRanges(dyn *model.DynValue,
	env *cel.Env, ceval *model.Evaluator) (*cel.Env, error) {
	ranges := tc.listValue(dyn)
	if tc.limits.RangeLimit >= 0 && len(ranges.Entries) > tc.limits.RangeLimit {
		reportID := ranges.Entries[tc.limits.RangeLimit].ID
		tc.reportErrorAtID(reportID,
			"range limit set to %d, but %d found",
			tc.limits.RangeLimit, len(ranges.Entries))
	}
	var rangeDecls []*exprpb.Decl
	for _, r := range ranges.Entries {
		rangeEnv, err := env.Extend(cel.Declarations(rangeDecls...))
		if err != nil {
			tc.reportErrorAtID(r.ID, err.Error())
			continue
		}
		rv := tc.mapValue(r)
		inField, keyFound := rv.GetField("in")
		if !keyFound {
			// This error would have been caught by schema checking.
			continue
		}
		inAst := tc.compileExpr(inField.Ref, rangeEnv, true)
		keyType := decls.Error
		valueType := decls.Error
		if inAst != nil {
			inType := inAst.ResultType()
			switch inType.TypeKind.(type) {
			case *exprpb.Type_MapType_:
				inMap := inType.GetMapType()
				keyType = inMap.GetKeyType()
				valueType = inMap.GetValueType()
			case *exprpb.Type_ListType_:
				inList := inType.GetListType()
				keyType = decls.Int
				valueType = inList.GetElemType()
			}
		}
		iterRange := &model.Range{
			ID:   r.ID,
			Expr: inAst,
		}
		idxField, idxFound := rv.GetField("index")
		keyField, keyFound := rv.GetField("key")
		valField, valFound := rv.GetField("value")
		if !idxFound && !keyFound && !valFound {
			tc.reportErrorAtID(r.ID, "one of 'index', 'key', or 'value' fields must be set")
		}
		if idxFound && keyFound {
			tc.reportErrorAtID(r.ID, "either set 'index' or 'key', but not both")
		}
		if idxFound {
			iterRange.Key = decls.NewVar(tc.strValue(idxField.Ref), keyType)
			rangeDecls = append(rangeDecls, iterRange.Key)
		}
		if keyFound {
			iterRange.Key = decls.NewVar(tc.strValue(keyField.Ref), keyType)
			rangeDecls = append(rangeDecls, iterRange.Key)
		}
		if valFound {
			iterRange.Value = decls.NewVar(tc.strValue(valField.Ref), valueType)
			rangeDecls = append(rangeDecls, iterRange.Value)
		}
		ceval.Ranges = append(ceval.Ranges, iterRange)
	}
	// Return the productions environment which contains all terms and inputs to the template.
	return env.Extend(cel.Declarations(rangeDecls...))
}

func (tc *templateCompiler) compileTerms(dyn *model.DynValue,
	env *cel.Env, ceval *model.Evaluator, termLimit int) (*cel.Env, error) {
	terms := tc.mapValue(dyn)
	if termLimit >= 0 && len(terms.Fields) > termLimit {
		reportID := terms.Fields[termLimit].ID
		tc.reportErrorAtID(reportID,
			"term limit set to %d, but %d found",
			termLimit, len(terms.Fields))
	}
	termMap := make(map[string]*model.Term)
	var termDecls []*exprpb.Decl
	for _, t := range terms.Fields {
		// Term redeclaration is already handled as part of schema checking, but will lead to other
		// errors in Environment extension which could be confusing.
		if _, found := termMap[t.Name]; found {
			continue
		}
		termEnv, err := env.Extend(cel.Declarations(termDecls...))
		if err != nil {
			tc.reportErrorAtID(t.ID, err.Error())
			continue
		}
		termType := decls.Error
		termAst := tc.compileExpr(t.Ref, termEnv, true)
		term := model.NewTerm(t.Ref.ID, t.Name, termAst)
		if termAst != nil {
			termType = termAst.ResultType()
		}
		termMap[t.Name] = term
		ceval.Terms = append(ceval.Terms, term)
		termDecls = append(termDecls, decls.NewVar(t.Name, termType))
	}
	// Return the productions environment which contains all terms and inputs to the template.
	return env.Extend(cel.Declarations(termDecls...))
}

// compileExpr converts a dynamic value to a CEL AST.
//
// If the 'strict' flag is true, the value node must be a CEL expression, otherwise the value
// node for a string-like value may either be a CEL expression (if it parses) or a simple string
// literal.
func (tc *templateCompiler) compileExpr(dyn *model.DynValue, env *cel.Env, strict bool) *cel.Ast {
	loc, _ := tc.meta.LocationByID(dyn.ID)
	exprString, err := tc.buildExprString(dyn, env, strict)
	if err != nil {
		return nil
	}
	relSrc := tc.src.Relative(exprString, loc.Line(), loc.Column())
	ast, iss := env.CompileSource(relSrc)
	if iss.Err() == nil {
		return ast
	}
	tc.reportIssues(iss)
	return nil
}

func (tc *templateCompiler) buildExprString(dyn *model.DynValue, env *cel.Env, strict bool) (string, error) {
	switch v := dyn.Value().(type) {
	case bool:
		return strconv.FormatBool(v), nil
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), nil
	case int64:
		return strconv.FormatInt(v, 10), nil
	case types.Null:
		return "null", nil
	case model.PlainTextValue:
		return strconv.Quote(string(v)), nil
	case *model.MultilineStringValue:
		loc, _ := tc.meta.LocationByID(dyn.ID)
		ast := tc.compileExprString(dyn.ID, v.Raw, loc, env, strict)
		if ast != nil {
			return v.Raw, nil
		}
		if strict {
			return "''", errors.New("error")
		}
		// non-strict parse which falls back to a plain text literal.
		return strconv.Quote(strings.TrimSpace(v.Value)), nil
	case string:
		loc, _ := tc.meta.LocationByID(dyn.ID)
		ast := tc.compileExprString(dyn.ID, v, loc, env, strict)
		if ast != nil {
			return v, nil
		}
		if strict {
			return "", errors.New("error")
		}
		return strconv.Quote(v), nil
	case uint64:
		return strconv.FormatUint(uint64(v), 10) + "u", nil
	case *model.ListValue:
		var buf strings.Builder
		buf.WriteString("[")
		cnt := len(v.Entries)
		for i, e := range v.Entries {
			str, err := tc.buildExprString(e, env, strict)
			if err != nil {
				return "", err
			}
			buf.WriteString(str)
			if i < cnt-1 {
				buf.WriteString(", ")
			}
		}
		buf.WriteString("]")
		return buf.String(), nil
	case *model.MapValue:
		var buf strings.Builder
		buf.WriteString("{")
		cnt := len(v.Fields)
		for i, f := range v.Fields {
			buf.WriteString(strconv.Quote(f.Name))
			buf.WriteString(": ")
			str, err := tc.buildExprString(f.Ref, env, strict)
			if err != nil {
				return "", err
			}
			buf.WriteString(str)
			if i < cnt-1 {
				buf.WriteString(", ")
			}
		}
		buf.WriteString("}")
		return buf.String(), nil
	case time.Time:
		var buf strings.Builder
		buf.WriteString("timestamp('")
		buf.WriteString(v.Format(time.RFC3339))
		buf.WriteString("')")
		str := buf.String()
		return str, nil
	default:
		// TODO: handle bytes
		return "", nil
	}
}

func (tc *templateCompiler) compileExprString(id int64,
	val string, loc common.Location, env *cel.Env, strict bool) *cel.Ast {
	relSrc := tc.src.Relative(val, loc.Line(), loc.Column())
	ast, iss := env.ParseSource(relSrc)
	if iss.Err() == nil {
		// If the expression parses, then it's probably CEL.
		// Report type-check issues if they are encountered and strict flag is true.
		ast, iss = env.Check(ast)
		if iss.Err() != nil && strict {
			tc.reportIssues(iss)
			return nil
		}
		return ast
	}
	if strict {
		tc.reportIssues(iss)
		return nil
	}
	return nil
}

func (tc *templateCompiler) newEnv(name string, ctmpl *model.Template) (*cel.Env, error) {
	env, found := tc.reg.FindExprEnv(name)
	if !found {
		return nil, fmt.Errorf("no such environment: %s", name)
	}
	metadataOpt :=
		cel.Declarations(
			decls.NewVar("template", decls.NewMapType(decls.String, decls.String)),
			decls.NewVar("instance", decls.NewMapType(decls.String, decls.String)),
		)
	env, err := env.Extend(metadataOpt)
	if err != nil {
		return nil, err
	}

	if ctmpl.RuleTypes == nil {
		return env, nil
	}
	opts, err := ctmpl.RuleTypes.EnvOptions(env.TypeProvider())
	if err != nil {
		return nil, err
	}
	return env.Extend(opts...)
}

type dynCompiler struct {
	reg    *compReg
	limits *limits.Limits
	src    *model.Source
	meta   model.SourceMetadata
	errors *common.Errors
}

func (dc *dynCompiler) boolValue(dyn *model.DynValue) bool {
	s, ok := dyn.Value().(bool)
	if ok {
		return s
	}
	dc.reportErrorAtID(dyn.ID, "expected bool type, found: %s", dyn.DeclType())
	return false
}

func (dc *dynCompiler) strValue(dyn *model.DynValue) string {
	s, ok := dyn.Value().(string)
	if ok {
		return s
	}
	dc.reportErrorAtID(dyn.ID, "expected string type, found: %s", dyn.DeclType())
	return ""
}

func (dc *dynCompiler) listValue(dyn *model.DynValue) *model.ListValue {
	l, ok := dyn.Value().(*model.ListValue)
	if ok {
		return l
	}
	dc.reportErrorAtID(dyn.ID, "expected list type, found: %v", dyn.DeclType())
	return model.NewListValue()
}

func (dc *dynCompiler) mapValue(dyn *model.DynValue) *model.MapValue {
	m, ok := dyn.Value().(*model.MapValue)
	if ok {
		return m
	}
	dc.reportErrorAtID(dyn.ID, "expected map type, found: %v", dyn.DeclType())
	return model.NewMapValue()
}

func (dc *dynCompiler) mapFieldStringValueOrEmpty(dyn *model.DynValue,
	fieldName string) string {
	m := dc.mapValue(dyn)
	field, found := m.GetField(fieldName)
	if !found {
		// do not report an error as a required field should be reported
		// by the schema checking step.
		return ""
	}
	switch v := field.Ref.Value().(type) {
	case string:
		return v
	case model.PlainTextValue:
		return string(v)
	case *model.MultilineStringValue:
		return v.Value
	default:
		dc.reportErrorAtID(dyn.ID,
			"unexpected field type: field=%s got=%T wanted=%v",
			fieldName, field.Ref.Value(), model.StringType)
		return ""
	}
}

func (dc *dynCompiler) checkSchema(dyn *model.DynValue, schema *model.OpenAPISchema) {
	schema = dc.resolveSchemaRef(dyn, schema)
	schemaType := schema.DeclType()
	valueType := dyn.DeclType()
	if !assignableToType(valueType, schemaType) {
		dc.reportErrorAtID(dyn.ID,
			"value not assignable to schema type: value=%v, schema=%v",
			valueType, schemaType)
		return
	}
	if schemaType.IsMap() || schemaType.IsObject() {
		dc.checkMapSchema(dyn, schema)
	} else if schemaType.IsList() {
		dc.checkListSchema(dyn, schema)
	} else if schemaType != model.AnyType {
		dc.checkPrimitiveSchema(dyn, schema)
	}
}

func (dc *dynCompiler) compileOpenAPISchema(dyn *model.DynValue, schema *model.OpenAPISchema, permitTypeParam bool) {
	schema.Title = dc.mapFieldStringValueOrEmpty(dyn, "title")
	schema.Description = dc.mapFieldStringValueOrEmpty(dyn, "description")
	schema.Type = dc.mapFieldStringValueOrEmpty(dyn, "type")
	schema.TypeRef = dc.mapFieldStringValueOrEmpty(dyn, "$ref")
	schema.Format = dc.mapFieldStringValueOrEmpty(dyn, "format")
	m := dc.mapValue(dyn)
	typeParam, found := m.GetField("type_param")
	if found {
		if !permitTypeParam {
			dc.reportErrorAtID(typeParam.ID,
				"type_param is only supported in environment declarations")
		}
		schema.TypeParam = dc.strValue(typeParam.Ref)
	}
	elem, found := m.GetField("items")
	if found {
		nested := model.NewOpenAPISchema()
		schema.Items = nested
		dc.compileOpenAPISchema(elem.Ref, nested, permitTypeParam)
	}
	elem, found = m.GetField("enum")
	if found {
		enums := dc.listValue(elem.Ref)
		for _, e := range enums.Entries {
			schema.Enum = append(schema.Enum, dc.convertToPrimitive(e))
		}
	}
	elem, found = m.GetField("required")
	if found {
		reqs := dc.listValue(elem.Ref)
		for _, el := range reqs.Entries {
			req := dc.strValue(el)
			if len(req) != 0 {
				schema.Required = append(schema.Required, string(req))
			}
		}
	}
	elem, found = m.GetField("properties")
	if found {
		obj := dc.mapValue(elem.Ref)
		for _, field := range obj.Fields {
			nested := model.NewOpenAPISchema()
			schema.Properties[field.Name] = nested
			dc.compileOpenAPISchema(field.Ref, nested, permitTypeParam)
		}
	}
	elem, found = m.GetField("additionalProperties")
	if found {
		nested := model.NewOpenAPISchema()
		schema.AdditionalProperties = nested
		dc.compileOpenAPISchema(elem.Ref, nested, permitTypeParam)
	}
	elem, found = m.GetField("default")
	if found {
		schema.DefaultValue = dc.convertToSchemaType(elem.Ref.ID, elem.Ref.Value(), schema)
	}
	elem, found = m.GetField("metadata")
	if found {
		meta := dc.mapValue(elem.Ref)
		for _, mf := range meta.Fields {
			val := dc.strValue(mf.Ref)
			schema.Metadata[mf.Name] = val
			if mf.Name == "custom_type" &&
				(schema.Type != "object" || schema.AdditionalProperties != nil) {
				dc.reportErrorAtID(
					mf.Ref.ID,
					"custom type may not be specified on non-object schema element")
			}
		}
	}
	dc.validateTypeDef(dyn, schema.Type)
}

func (dc *dynCompiler) validateTypeDef(dyn *model.DynValue, typeName string) {
	m := dc.mapValue(dyn)
	p, hasProps := m.GetField("properties")
	ap, hasAdditionalProps := m.GetField("additionalProperties")
	_, hasItems := m.GetField("items")
	ed, hasEnumDesc := m.GetField("enumDescriptions")
	_, hasEnum := m.GetField("enum")

	if hasProps && hasAdditionalProps {
		dc.reportErrorAtID(ap.Ref.ID,
			"invalid type. properties set, additionalProperties must not be set.")
	}
	if hasProps && typeName != "object" {
		dc.reportErrorAtID(p.Ref.ID,
			"invalid type. properties set, expected object type, found: %s.",
			typeName)
	}
	if hasAdditionalProps && typeName != "object" {
		dc.reportErrorAtID(ap.Ref.ID,
			"invalid type. additionalProperties set, expected object type, found: %s.",
			typeName)
	}
	if hasItems {
		if typeName != "array" {
			dc.reportErrorAtID(dyn.ID,
				"invalid type. items set, expected array type, found: %s.",
				typeName)
		}
		if hasProps {
			dc.reportErrorAtID(p.Ref.ID,
				"invalid type. items set, properties must not be set.")
		}
		if hasAdditionalProps {
			dc.reportErrorAtID(ap.Ref.ID,
				"invalid type. items set, additionalProperties must not be set.")
		}
	}
	if hasEnumDesc && !hasEnum {
		dc.reportErrorAtID(ed.Ref.ID,
			"invalid type. enumDescriptions set, enum must be set.")
	}
}

func (dc *dynCompiler) resolveSchemaRef(dyn *model.DynValue, schema *model.OpenAPISchema) *model.OpenAPISchema {
	if schema.TypeRef == "" {
		return schema
	}
	var found bool
	typeRef := schema.TypeRef
	schema, found = dc.reg.FindSchema(typeRef)
	if !found {
		dc.reportErrorAtID(dyn.ID, "no such schema: name=%s", typeRef)
		schema = model.AnySchema
	}
	return schema
}

func (dc *dynCompiler) checkPrimitiveSchema(dyn *model.DynValue, schema *model.OpenAPISchema) {
	// Ensure the value matches the schema type and format.
	err := dyn.SetValue(dc.convertToSchemaType(dyn.ID, dyn.Value(), schema))
	if err != nil {
		dc.reportErrorAtID(dyn.ID, err.Error())
		return
	}
	// Check whether the input value is one of the enumerated types.
	if len(schema.Enum) > 0 {
		for _, e := range schema.Enum {
			val := dc.convertToSchemaType(dyn.ID, e, schema)
			// Note: deep equality won't work for list, map values.
			if reflect.DeepEqual(dyn.Value(), val) {
				return
			}
		}
		dc.reportErrorAtID(dyn.ID, "invalid enum value: %s. must be one of: %v", dyn.Value(), schema.Enum)
	}
}

func (dc *dynCompiler) checkListSchema(dyn *model.DynValue, schema *model.OpenAPISchema) {
	lv := dc.listValue(dyn)
	entrySchema := dc.resolveSchemaRef(dyn, schema.Items)
	for _, entry := range lv.Entries {
		dc.checkSchema(entry, entrySchema)
	}
}

func (dc *dynCompiler) checkMapSchema(dyn *model.DynValue, schema *model.OpenAPISchema) {
	// Check whether the configured properties have been declared and if so, whether they
	// schema-check correctly.
	mv := dc.mapValue(dyn)
	fields := make(map[string]*model.Field, len(mv.Fields))
	for _, f := range mv.Fields {
		_, found := fields[f.Name]
		if found {
			dc.reportErrorAtID(f.ID, "field redeclaration error: %s", f.Name)
		}
		fields[f.Name] = f
		prop, found := schema.FindProperty(f.Name)
		if !found {
			dc.reportErrorAtID(f.ID, "no such field: %s", f.Name)
			continue
		}
		dc.checkSchema(f.Ref, prop)
	}
	// Check whether required fields are missing.
	if schema.Required != nil {
		missing := []string{}
		for _, reqField := range schema.Required {
			_, found := fields[reqField]
			if !found {
				missing = append(missing, reqField)
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			dc.reportErrorAtID(dyn.ID, "missing required field(s): %s", missing)
		}
	}
	// Set default values, if it is possible for them to be set.
	// Note, schema checking will validate the default properties as well to ensure proper type
	// conversion of the default values.
	for prop, propSchema := range schema.Properties {
		if propSchema.DefaultValue == nil {
			continue
		}
		_, defined := fields[prop]
		if defined {
			continue
		}
		field := model.NewField(0, prop)
		err := field.Ref.SetValue(dc.convertToSchemaType(dyn.ID, propSchema.DefaultValue, propSchema))
		if err != nil {
			dc.reportErrorAtID(dyn.ID, err.Error())
			continue
		}
		dc.checkSchema(field.Ref, propSchema)
		mv.AddField(field)
	}
}

func (dc *dynCompiler) convertToPrimitive(dyn *model.DynValue) interface{} {
	switch v := dyn.Value().(type) {
	case bool, []byte, float64, int64, string, uint64, time.Time, types.Null:
		return v
	case *model.MultilineStringValue:
		return v.Value
	case model.PlainTextValue:
		return string(v)
	default:
		dc.reportErrorAtID(dyn.ID, "expected primitive type, found=%v", dyn.DeclType())
		return ""
	}
}

func (dc *dynCompiler) convertToSchemaType(id int64, val interface{},
	schema *model.OpenAPISchema) interface{} {
	switch v := val.(type) {
	case bool, float64, int64, uint64, time.Duration, time.Time:
		return v
	case string, model.PlainTextValue, *model.MultilineStringValue:
		str := ""
		switch s := v.(type) {
		case model.PlainTextValue:
			str = string(s)
		case *model.MultilineStringValue:
			str = s.Value
		default:
			str = s.(string)
		}
		switch schema.DeclType() {
		case model.DurationType:
			t, err := time.ParseDuration(str)
			if err != nil {
				dc.reportErrorAtID(id, "duration must be a number followed by a valid time"+
					" unit: 'ns', 'us', 'ms', 's', 'm', 'h': value=%s", str)
			}
			return t
		case model.TimestampType:
			t, err := time.Parse(time.RFC3339, str)
			if err != nil {
				dc.reportErrorAtID(id,
					"timestamp must be RFC3339 format, e.g. YYYY-DD-MMTHH:MM:SSZ: value=%s",
					str)
				return str
			}
			return t
		case model.BytesType:
			if schema.Format == "byte" {
				b, err := base64.StdEncoding.DecodeString(str)
				if err != nil {
					dc.reportErrorAtID(id,
						"byte encoding must be base64. value=%s", str)
					return str
				}
				return b
			}
			return []byte(str)
		case model.IntType:
			i, err := strconv.ParseInt(str, 10, 64)
			if err != nil {
				dc.reportErrorAtID(id, "invalid integer format. value=%s", str)
				return str
			}
			return i
		case model.UintType:
			u, err := strconv.ParseUint(str, 10, 64)
			if err != nil {
				dc.reportErrorAtID(id, "invalid unsigned integer format. value=%s", str)
				return str
			}
			return u
		default:
			return v
		}
	case []interface{}:
		lv := model.NewListValue()
		itemSchema := model.AnySchema
		if schema.Items != nil {
			itemSchema = schema.Items
		}
		for _, e := range v {
			ev := dc.convertToSchemaType(id, e, itemSchema)
			elem := model.NewEmptyDynValue()
			err := elem.SetValue(ev)
			if err != nil {
				dc.reportErrorAtID(id, err.Error())
			} else {
				lv.Append(elem)
			}
		}
		return lv
	case map[string]interface{}:
		mv := model.NewMapValue()
		for name, e := range v {
			f := model.NewField(0, name)
			propSchema, found := schema.FindProperty(name)
			if !found {
				propSchema = model.AnySchema
				if schema.AdditionalProperties != nil {
					propSchema = schema.AdditionalProperties
				}
			}
			err := f.Ref.SetValue(dc.convertToSchemaType(id, e, propSchema))
			if err != nil {
				dc.reportErrorAtID(id, err.Error())
			}
		}
		return mv
	case *model.ListValue, *model.MapValue:
		return v
	default:
		dc.reportErrorAtID(id, "unsupported type value for schema property. value=%v (%T), schema=%v", val, val, schema)
		return v
	}
}

func (dc *dynCompiler) reportIssues(iss *cel.Issues) {
	dc.errors = dc.errors.Append(iss.Errors())
}

func (dc *dynCompiler) reportError(msg string, args ...interface{}) {
	dc.reportErrorAtLoc(common.NoLocation, msg, args...)
}

func (dc *dynCompiler) reportErrorAtLoc(loc common.Location, msg string, args ...interface{}) {
	dc.errors.ReportError(loc, msg, args...)
}

func (dc *dynCompiler) reportErrorAtID(id int64, msg string, args ...interface{}) {
	loc, found := dc.meta.LocationByID(id)
	if !found {
		loc = common.NoLocation
	}
	dc.reportErrorAtLoc(loc, msg, args...)
}

func assignableToType(valType, schemaType *model.DeclType) bool {
	if valType == schemaType || schemaType == model.AnyType {
		return true
	}
	if valType.IsMap() && (schemaType.IsMap() || schemaType.IsObject()) {
		return true
	}
	if valType.IsList() && schemaType.IsList() {
		return true
	}
	if valType == model.StringType || valType == model.PlainTextType {
		switch schemaType {
		case model.BytesType,
			model.DurationType,
			model.IntType,
			model.StringType,
			model.TimestampType,
			model.UintType,
			model.PlainTextType:
			return true
		}
	}
	if valType == model.TimestampType {
		switch schemaType {
		case model.StringType, model.PlainTextType:
			return true
		}
	}
	if valType == model.UintType && schemaType == model.IntType {
		return true
	}
	return false
}

type compReg struct {
	*model.Registry
	ruleSchema *model.OpenAPISchema
}

func (reg *compReg) FindSchema(name string) (*model.OpenAPISchema, bool) {
	if name == "#templateRuleSchema" {
		return reg.ruleSchema, true
	}
	return reg.Registry.FindSchema(name)
}
