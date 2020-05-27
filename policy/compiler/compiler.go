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

// Package compiler contains a suite of tools for convering parsed representations of CEL Policy
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

	"github.com/golang/protobuf/proto"

	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

// NewCompiler creates a new Compiler instance with the given Registry and CEL evaluation options.
func NewCompiler(reg model.Registry,
	l *limits.Limits,
	evalOpts ...cel.ProgramOption) *Compiler {
	return &Compiler{
		evalOpts: evalOpts,
		reg:      reg,
		limits:   l,
	}
}

// Compiler type-checks and compiles a raw model.ParsedValue into a strongly typed in-memory
// representation of a template or policy instance.
type Compiler struct {
	evalOpts []cel.ProgramOption
	reg      model.Registry
	limits   *limits.Limits
}

// CompileInstance type-checks and validates a parsed representation of a policy instance whose
// format and validation logic is also determined by policy template referenced in the policy
// instance 'kind' field.
func (c *Compiler) CompileInstance(src *model.Source,
	inst *model.ParsedValue) (*model.Instance, *cel.Issues) {
	return c.newInstanceCompiler(src, inst).compile()
}

// CompileTemplate type-checks and validates a parsed representation of a policy template.
func (c *Compiler) CompileTemplate(src *model.Source,
	tmpl *model.ParsedValue) (*model.Template, *cel.Issues) {
	return c.newTemplateCompiler(src, tmpl).compile()
}

func (c *Compiler) newInstanceCompiler(src *model.Source,
	inst *model.ParsedValue) *instanceCompiler {
	dc := c.newDynCompiler(src, inst)
	dyn := model.NewDynValue(inst.ID, inst.Value)
	tmplName := dc.mapFieldStringValueOrEmpty(dyn, "kind")
	tmpl, found := dc.reg.FindTemplate(tmplName)
	if !found {
		// report an error and return
		dc.reportError("no such template: %s", tmplName)
		return nil
	}
	if tmpl.RuleTypes != nil {
		dc.reg.ruleSchema = tmpl.RuleTypes.Schema
	}
	dc.checkSchema(dyn, model.InstanceSchema)
	return &instanceCompiler{
		dynCompiler: dc,
		dyn:         dyn,
		rt:          tmpl.RuleTypes,
		tmpl:        tmpl,
		evalOpts:    c.evalOpts,
	}
}

func (c *Compiler) newTemplateCompiler(src *model.Source,
	tmpl *model.ParsedValue) *templateCompiler {
	dc := c.newDynCompiler(src, tmpl)
	dyn := model.NewDynValue(tmpl.ID, tmpl.Value)
	dc.checkSchema(dyn, model.TemplateSchema)
	return &templateCompiler{
		dynCompiler: dc,
		dyn:         dyn,
	}
}

func (c *Compiler) newDynCompiler(src *model.Source,
	pv *model.ParsedValue) *dynCompiler {
	return &dynCompiler{
		reg: &compReg{
			Registry: c.reg,
		},
		limits: c.limits,
		src:    src,
		info:   pv.Info,
		errors: common.NewErrors(src),
	}
}

type instanceCompiler struct {
	*dynCompiler
	dyn      *model.DynValue
	rt       *model.RuleTypes
	tmpl     *model.Template
	evalOpts []cel.ProgramOption
}

func (ic *instanceCompiler) compile() (*model.Instance, *cel.Issues) {
	cinst := model.NewInstance(ic.info)
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
	rules, found := m.GetField("rules")
	if found {
		ruleSet := ic.listValue(rules.Ref)
		cinst.Rules = make([]model.Rule, len(ruleSet.Entries))
		for i, rule := range ruleSet.Entries {
			cinst.Rules[i] = ic.convertToRule(rule)
		}
	}
	rule, found := m.GetField("rule")
	if found {
		r := ic.convertToRule(rule.Ref)
		cinst.Rules = []model.Rule{r}
	}
	exec, err := runtime.NewTemplate(ic.reg, ic.tmpl, ic.limits, ic.evalOpts...)
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
				valsField, _ := mv.GetField("values")
				valList := ic.listValue(valsField.Ref)
				vals := make([]interface{}, len(valList.Entries))
				for i, v := range valList.Entries {
					vals[i] = ic.convertToPrimitive(v)
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
	ctmpl := model.NewTemplate(tc.info)
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
		tc.compileOpenAPISchema(schemaDef.Ref, schema)
		// TODO: attempt schema type unification post-compile
		// hashSchema(ctmpl.RuleSchema)
		ctmpl.RuleTypes = model.NewRuleTypes(ctmpl.Metadata.Name, schema)
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

func (tc *templateCompiler) compileOpenAPISchema(dyn *model.DynValue,
	schema *model.OpenAPISchema) {
	schema.Title = tc.mapFieldStringValueOrEmpty(dyn, "title")
	schema.Description = tc.mapFieldStringValueOrEmpty(dyn, "description")
	schema.Type = tc.mapFieldStringValueOrEmpty(dyn, "type")
	schema.TypeRef = tc.mapFieldStringValueOrEmpty(dyn, "$ref")
	schema.Format = tc.mapFieldStringValueOrEmpty(dyn, "format")
	m := tc.mapValue(dyn)
	elem, found := m.GetField("items")
	if found {
		nested := model.NewOpenAPISchema()
		schema.Items = nested
		tc.compileOpenAPISchema(elem.Ref, nested)
	}
	elem, found = m.GetField("enum")
	if found {
		enums := tc.listValue(elem.Ref)
		for _, e := range enums.Entries {
			schema.Enum = append(schema.Enum, tc.convertToPrimitive(e))
		}
	}
	elem, found = m.GetField("metadata")
	if found {
		meta := tc.mapValue(elem.Ref)
		for _, mf := range meta.Fields {
			val := tc.strValue(mf.Ref)
			if len(val) != 0 {
				schema.Metadata[mf.Name] = string(val)
			}
		}
	}
	elem, found = m.GetField("required")
	if found {
		reqs := tc.listValue(elem.Ref)
		for _, el := range reqs.Entries {
			req := tc.strValue(el)
			if len(req) != 0 {
				schema.Required = append(schema.Required, string(req))
			}
		}
	}
	elem, found = m.GetField("properties")
	if found {
		obj := tc.mapValue(elem.Ref)
		for _, field := range obj.Fields {
			nested := model.NewOpenAPISchema()
			schema.Properties[field.Name] = nested
			tc.compileOpenAPISchema(field.Ref, nested)
		}
	}
	elem, found = m.GetField("additionalProperties")
	if found {
		nested := model.NewOpenAPISchema()
		schema.AdditionalProperties = nested
		tc.compileOpenAPISchema(elem.Ref, nested)
	}
	elem, found = m.GetField("default")
	if found {
		schema.DefaultValue = tc.convertToSchemaType(elem.Ref.ID, elem.Ref.Value, schema)
	}
}

func (tc *templateCompiler) compileValidator(dyn *model.DynValue, ctmpl *model.Template) {
	val := tc.mapValue(dyn)
	if len(val.Fields) == 0 {
		// TODO: maybe not intentional that the validator is empty.
		return
	}
	validator, productionsEnv := tc.buildProductionsEnv(dyn, ctmpl)
	if validator == nil {
		// error occurred, will have been recorded elsewhere.
		return
	}
	prods, found := val.GetField("productions")
	if found {
		tc.compileValidatorOutputDecisions(prods.Ref, productionsEnv, validator)
	} else {
		// TODO: generate a warning, but not an error.
	}
	ctmpl.Validator = validator
}

func (tc *templateCompiler) compileValidatorOutputDecisions(
	prods *model.DynValue, env *cel.Env, ceval *model.Evaluator) {
	productions := tc.listValue(prods)
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
		outTxt := fmt.Sprintf("{'message': %s}", msgTxt)
		if detTxt != "" {
			outTxt = fmt.Sprintf("{'message': %s, 'details': %s}", msgTxt, detTxt)
		}
		outDyn := model.NewDynValue(p.ID, outTxt)
		ast := tc.compileExpr(outDyn, env, true)
		outDec := model.NewDecision()
		outDec.Name = "policy.invalid"
		outDec.Output = ast
		rule.Decisions = append(rule.Decisions, outDec)
		prodRules[i] = rule
	}
	ceval.Productions = prodRules
}

func (tc *templateCompiler) compileEvaluator(dyn *model.DynValue, ctmpl *model.Template) {
	eval := tc.mapValue(dyn)
	if len(eval.Fields) == 0 {
		return
	}
	evaluator, productionsEnv := tc.buildProductionsEnv(dyn, ctmpl)
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
	ctmpl *model.Template) (*model.Evaluator, *cel.Env) {
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
		productionsEnv, err = tc.compileTerms(terms.Ref, productionsEnv, evaluator)
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
	if len(ranges.Entries) > tc.limits.RangeLimit {
		tc.reportErrorAtID(dyn.ID,
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
	env *cel.Env, ceval *model.Evaluator) (*cel.Env, error) {
	terms := tc.mapValue(dyn)
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
			for _, varName := range getVars(termAst) {
				input, found := termMap[varName]
				if found {
					term.InputTerms[varName] = input
				}
			}
		}
		termMap[t.Name] = term
		ceval.Terms = append(ceval.Terms, term)
		termDecls = append(termDecls, decls.NewIdent(t.Name, termType, nil))
	}
	// Return the productions environment which contains all terms and inputs to the template.
	return env.Extend(cel.Declarations(termDecls...))
}

// compileExpr converts a dynamic value to a CEL AST.
//
// If the 'strict' flag is true, the value node must be a CEL expression, otherwise the value
// node for a string-like value may either be a CEL expression (if it parses) or a simple string
// literal.
func (tc *templateCompiler) compileExpr(dyn *model.DynValue,
	env *cel.Env, strict bool) *cel.Ast {
	loc, _ := tc.info.LocationByID(dyn.ID)
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

func (tc *templateCompiler) buildExprString(
	dyn *model.DynValue, env *cel.Env, strict bool) (string, error) {
	switch v := dyn.Value.(type) {
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
		loc, _ := tc.info.LocationByID(dyn.ID)
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
		loc, _ := tc.info.LocationByID(dyn.ID)
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
		// Report type-check issues if they are encountered.
		ast, iss = env.Check(ast)
		if iss.Err() != nil {
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

func (tc *templateCompiler) newEnv(envName string, ctmpl *model.Template) (*cel.Env, error) {
	env, found := tc.reg.FindEnv(envName)
	if !found {
		return nil, fmt.Errorf("no such environment: %s", envName)
	}
	if ctmpl.RuleTypes == nil {
		return env, nil
	}
	return env.Extend(
		ctmpl.RuleTypes.EnvOptions(env.TypeProvider())...,
	)
}

type dynCompiler struct {
	reg    *compReg
	limits *limits.Limits
	src    *model.Source
	info   *model.SourceInfo
	errors *common.Errors
}

func (dc *dynCompiler) strValue(dyn *model.DynValue) string {
	s, ok := dyn.Value.(string)
	if ok {
		return s
	}
	dc.reportErrorAtID(dyn.ID, "expected string type, found: %s", dyn.ModelType())
	return ""
}

func (dc *dynCompiler) listValue(dyn *model.DynValue) *model.ListValue {
	l, ok := dyn.Value.(*model.ListValue)
	if ok {
		return l
	}
	dc.reportErrorAtID(dyn.ID, "expected list type, found: %s", dyn.ModelType())
	return model.NewListValue()
}

func (dc *dynCompiler) mapValue(dyn *model.DynValue) *model.MapValue {
	m, ok := dyn.Value.(*model.MapValue)
	if ok {
		return m
	}
	dc.reportErrorAtID(dyn.ID, "expected map type, found: %s", dyn.ModelType())
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
	switch v := field.Ref.Value.(type) {
	case string:
		return v
	case model.PlainTextValue:
		return string(v)
	case *model.MultilineStringValue:
		return v.Value
	default:
		dc.reportErrorAtID(dyn.ID,
			"unexpected field type: field=%s got=%T wanted=%s",
			fieldName, field.Ref.Value, model.StringType)
		return ""
	}
}

func (dc *dynCompiler) checkSchema(dyn *model.DynValue, schema *model.OpenAPISchema) {
	schema = dc.resolveSchemaRef(dyn, schema)
	modelType := schema.ModelType()
	valueType := dyn.ModelType()
	if !assignableToType(valueType, modelType) {
		dc.reportErrorAtID(dyn.ID,
			"value not assignable to schema type: value=%s, schema=%s",
			valueType, modelType)
		return
	}
	switch modelType {
	case model.MapType:
		dc.checkMapSchema(dyn, schema)
	case model.ListType:
		dc.checkListSchema(dyn, schema)
	case model.AnyType:
		return
	default:
		dc.checkPrimitiveSchema(dyn, schema)
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
	}
	return schema
}

func (dc *dynCompiler) checkPrimitiveSchema(dyn *model.DynValue, schema *model.OpenAPISchema) {
	// Ensure the value matches the schema type and format.
	dyn.Value = dc.convertToSchemaType(dyn.ID, dyn.Value, schema)

	// Check whether the input value is one of the enumerated types.
	if len(schema.Enum) > 0 {
		for _, e := range schema.Enum {
			val := dc.convertToSchemaType(dyn.ID, e, schema)
			// Note: deep equality won't work for list, map values.
			if reflect.DeepEqual(dyn.Value, val) {
				return
			}
		}
		dc.reportErrorAtID(dyn.ID,
			"invalid enum value: %s. must be one of: %v",
			dyn.Value, schema.Enum)
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
		field.Ref.Value = dc.convertToSchemaType(dyn.ID,
			propSchema.DefaultValue, propSchema)
		dc.checkSchema(field.Ref, propSchema)
		mv.AddField(field)
	}
}

func (dc *dynCompiler) convertToPrimitive(dyn *model.DynValue) interface{} {
	switch v := dyn.Value.(type) {
	case bool, []byte, float64, int64, string, uint64, time.Time, types.Null:
		return v
	case *model.MultilineStringValue:
		return v.Value
	case model.PlainTextValue:
		return string(v)
	default:
		dc.reportErrorAtID(dyn.ID, "expected primitive type, found=%s", dyn.ModelType())
		return ""
	}
}

func (dc *dynCompiler) convertToSchemaType(id int64, val interface{},
	schema *model.OpenAPISchema) interface{} {
	switch v := val.(type) {
	case bool, float64, int64, uint64:
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
		switch schema.ModelType() {
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
		default:
			return v
		}
	case []interface{}:
		lv := model.NewListValue()
		itemSchema := schema.Items
		if itemSchema == nil {
			itemSchema = model.AnySchema
		}
		for _, e := range v {
			ev := dc.convertToSchemaType(id, e, schema.Items)
			elem := model.NewEmptyDynValue()
			elem.Value = ev
			lv.Append(elem)
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
			f.Ref.Value = dc.convertToSchemaType(id, e, propSchema)
		}
		return mv
	case *model.ListValue, *model.MapValue:
		return v
	default:
		dc.reportErrorAtID(id,
			"unsupported type value for schema property. value=%v (%T), schema=%v",
			val, val, schema)
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
	loc, found := dc.info.LocationByID(id)
	if !found {
		loc = common.NoLocation
	}
	dc.reportErrorAtLoc(loc, msg, args...)
}

func assignableToType(valType, schemaType string) bool {
	if valType == schemaType || schemaType == model.AnyType {
		return true
	}
	if valType == model.StringType || valType == model.PlainTextType {
		switch schemaType {
		case model.BytesType, model.StringType, model.TimestampType, model.PlainTextType:
			return true
		}
	}

	if valType == model.UintType && schemaType == model.IntType {
		return true
	}
	return false
}

func getVars(ast *cel.Ast) []string {
	ce, _ := cel.AstToCheckedExpr(ast)
	refMap := ce.GetReferenceMap()
	var vars []string
	for _, ref := range refMap {
		if ref.GetName() != "" && ref.GetValue() == nil {
			// Variable
			vars = append(vars, ref.GetName())
		}
	}
	return vars
}

type compReg struct {
	model.Registry
	ruleSchema *model.OpenAPISchema
}

func (reg *compReg) FindSchema(name string) (*model.OpenAPISchema, bool) {
	if name == "#templateRuleSchema" {
		return reg.ruleSchema, true
	}
	return reg.Registry.FindSchema(name)
}
