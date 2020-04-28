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
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common"
	"github.com/google/cel-go/common/types"

	"github.com/google/cel-policy-templates-go/policy/model"

	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

type Compiler struct {
	reg Registry
}

func (c *Compiler) CompileTemplate(src *model.Source, tmpl *model.ParsedValue) (*model.CompiledTemplate, *common.Errors) {
	tc := &templateCompiler{
		reg:    c.reg,
		src:    src,
		info:   tmpl.Info,
		errors: common.NewErrors(src),
	}
	dyn := model.NewDynValue(tmpl.ID, tmpl.Value)
	tc.checkSchema(dyn, model.TemplateSchema)
	ctmpl := model.NewCompiledTemplate()
	tc.compileTemplate(dyn, ctmpl)
	errs := tc.errors.GetErrors()
	if len(errs) != 0 {
		return nil, tc.errors
	}
	return ctmpl, tc.errors
}

type templateCompiler struct {
	reg    Registry
	src    *model.Source
	info   *model.SourceInfo
	errors *common.Errors
}

func (tc *templateCompiler) compileTemplate(dyn *model.DynValue, ctmpl *model.CompiledTemplate) {
	m := dyn.Value.(*model.MapValue)
	ctmpl.APIVersion = tc.mapFieldStringValueOrEmpty(dyn.ID, m, "apiVersion")
	ctmpl.Description = tc.mapFieldStringValueOrEmpty(dyn.ID, m, "description")
	ctmpl.Kind = tc.mapFieldStringValueOrEmpty(dyn.ID, m, "kind")
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
}

func (tc *templateCompiler) compileMetadata(dyn *model.DynValue, cmeta *model.CompiledMetadata) {
	// TODO: attach the template metadata.
	m, ok := dyn.Value.(*model.MapValue)
	if !ok {
		tc.reportErrorAtID(dyn.ID,
			"unexpected metadata type: got=%s, wanted=map",
			dyn.Value.ModelType())
		return
	}
	cmeta.Name = tc.mapFieldStringValueOrEmpty(dyn.ID, m, "name")
	cmeta.UID = tc.mapFieldStringValueOrEmpty(dyn.ID, m, "uid")
	ns, found := m.GetField("namespace")
	if found {
		cmeta.Namespace = string(ns.Ref.Value.(model.StringValue))
	} else {
		cmeta.Namespace = "default"
	}
	plural, found := m.GetField("pluralName")
	if found {
		cmeta.PluralName = string(plural.Ref.Value.(model.StringValue))
	} else if len(cmeta.Name) > 0 {
		cmeta.PluralName = cmeta.Name + "s"
	} else {
		// report error
	}
}

func (tc *templateCompiler) compileOpenAPISchema(dyn *model.DynValue,
	schema *model.OpenAPISchema) {
	m, ok := dyn.Value.(*model.MapValue)
	if !ok {
		tc.reportErrorAtID(dyn.ID,
			"unexpected rule schema type: got=%s, wanted=map",
			dyn.Value.ModelType())
		return
	}
	schema.Title = tc.mapFieldStringValueOrEmpty(dyn.ID, m, "title")
	schema.Description = tc.mapFieldStringValueOrEmpty(dyn.ID, m, "description")
	schema.Type = tc.mapFieldStringValueOrEmpty(dyn.ID, m, "type")
	schema.TypeRef = tc.mapFieldStringValueOrEmpty(dyn.ID, m, "$ref")
	schema.Format = tc.mapFieldStringValueOrEmpty(dyn.ID, m, "format")
	elem, found := m.GetField("items")
	if found {
		nested := model.NewOpenAPISchema()
		schema.Items = nested
		tc.compileOpenAPISchema(elem.Ref, nested)
	}
	elem, found = m.GetField("metadata")
	if found {
		meta, ok := elem.Ref.Value.(*model.MapValue)
		if !ok {
			tc.reportErrorAtID(elem.Ref.ID,
				"unexpected metadata type: got=%s, wanted=map",
				elem.Ref.Value.ModelType())
			meta = model.NewMapValue()
		}
		for _, mf := range meta.Fields {
			val, ok := mf.Ref.Value.(model.StringValue)
			if ok {
				schema.Metadata[mf.Name] = string(val)
			} else {
				tc.reportErrorAtID(mf.Ref.ID,
					"unexpected metadata value type: got=%s, wanted=string",
					mf.Ref.Value.ModelType())
			}
		}
	}
	elem, found = m.GetField("required")
	if found {
		reqs, ok := elem.Ref.Value.(*model.ListValue)
		if !ok {
			// report error, continue with empty list
			reqs = model.NewListValue()
		}
		for _, el := range reqs.Entries {
			req, ok := el.Value.(model.StringValue)
			if ok {
				schema.Required = append(schema.Required, string(req))
			} else {
				// report error
			}
		}
	}
	elem, found = m.GetField("properties")
	if found {
		obj, ok := elem.Ref.Value.(*model.MapValue)
		if !ok {
			obj = model.NewMapValue()
			// report error, but continue with empty map.
		}
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
}

func (tc *templateCompiler) compileValidator(dyn *model.DynValue,
	ctmpl *model.CompiledTemplate) {
	val := dyn.Value.(*model.MapValue)
	if len(val.Fields) == 0 {
		// TODO: maybe not intentional that the validator is empty.
		return
	}
	validator, prodsEnv := tc.buildProductionsEnv(dyn, ctmpl)
	if validator == nil {
		// error occurred, will have been recorded elsewhere.
		return
	}
	prods, found := val.GetField("productions")
	if found {
		tc.compileValidatorOutputDecisions(prods.Ref, prodsEnv, validator)
	} else {
		// TODO: generate a warning, but not an error.
	}
	ctmpl.Validator = validator
}

func (tc *templateCompiler) compileValidatorOutputDecisions(prods *model.DynValue,
	env *cel.Env, ceval *model.CompiledEvaluator) {
	productions := prods.Value.(*model.ListValue)
	prodRules := make([]*model.CompiledProduction, len(productions.Entries))
	for i, p := range productions.Entries {
		prod := p.Value.(*model.MapValue)
		match, _ := prod.GetField("match")
		matchAst := tc.compileExpr(match.Ref, env, true)
		rule := model.NewCompiledProduction(matchAst)
		// TODO: Add more structure checking here. For now, build a JSON object.
		msg, found := prod.GetField("message")
		msgTxt := "''"
		if found {
			ast := tc.compileExpr(msg.Ref, env, false)
			if ast != nil {
				msgTxt, _ = cel.AstToString(ast)
			}
		}
		det, found := prod.GetField("details")
		detTxt := "null"
		if found {
			ast := tc.compileExpr(det.Ref, env, false)
			if ast != nil {
				detTxt, _ = cel.AstToString(ast)
			}
		}
		// Note: this format will not yet work with structured outputs for the validator.
		outTxt := fmt.Sprintf("{'message': %s, 'details': %s}", msgTxt, detTxt)
		outDyn := model.NewDynValue(p.ID, model.StringValue(outTxt))
		ast := tc.compileExpr(outDyn, env, true)
		outDec := model.NewCompiledDecision()
		outDec.Decision = "policy.invalid"
		outDec.Output = ast
		rule.Decisions = append(rule.Decisions, outDec)
		prodRules[i] = rule
	}
	ceval.Productions = prodRules
}

func (tc *templateCompiler) compileEvaluator(dyn *model.DynValue,
	ctmpl *model.CompiledTemplate) {
	eval := dyn.Value.(*model.MapValue)
	if len(eval.Fields) == 0 {
		return
	}
	evaluator, prodsEnv := tc.buildProductionsEnv(dyn, ctmpl)
	if evaluator == nil {
		// Error occurred, would have been reported elsewhere.
		return
	}
	prods, found := eval.GetField("productions")
	if found {
		tc.compileEvaluatorOutputDecisions(prods.Ref, prodsEnv, evaluator)
	} else {
		tc.reportErrorAtID(dyn.ID, "evaluator missing productions field")
	}
	ctmpl.Evaluator = evaluator
}

func (tc *templateCompiler) compileEvaluatorOutputDecisions(prods *model.DynValue,
	env *cel.Env, ceval *model.CompiledEvaluator) {
	productions := prods.Value.(*model.ListValue)
	prodRules := make([]*model.CompiledProduction, len(productions.Entries))
	for i, p := range productions.Entries {
		prod := p.Value.(*model.MapValue)
		match, _ := prod.GetField("match")
		matchAst := tc.compileExpr(match.Ref, env, true)
		rule := model.NewCompiledProduction(matchAst)
		// TODO: Add more structure checking here. For now, build a JSON object.
		_, found := prod.GetField("decision")
		if found {
			outDec := tc.compileOutputDecision(prod, env)
			if outDec != nil {
				rule.Decisions = append(rule.Decisions, outDec)
			}
		}
		decs, found := prod.GetField("decisions")
		if found {
			decsList := decs.Ref.Value.(*model.ListValue)
			for _, elem := range decsList.Entries {
				tuple := elem.Value.(*model.MapValue)
				outDec := tc.compileOutputDecision(tuple, env)
				if outDec != nil {
					rule.Decisions = append(rule.Decisions, outDec)
				}
			}
		}
		prodRules[i] = rule
	}
	ceval.Productions = prodRules
}

func (tc *templateCompiler) compileOutputDecision(
	prod *model.MapValue,
	env *cel.Env) *model.CompiledDecision {
	outDec := model.NewCompiledDecision()
	dec, found := prod.GetField("decision")
	if found {
		decName := dec.Ref.Value.(model.StringValue)
		outDec.Decision = string(decName)
	}
	ref, found := prod.GetField("reference")
	if found {
		outDec.Reference = tc.compileExpr(ref.Ref, env, true)
	}
	output, found := prod.GetField("output")
	if !found {
		// report error
		return nil
	}
	outDec.Output = tc.compileExpr(output.Ref, env, false)
	return outDec
}

func (tc *templateCompiler) buildProductionsEnv(dyn *model.DynValue,
	ctmpl *model.CompiledTemplate) (*model.CompiledEvaluator, *cel.Env) {
	eval := dyn.Value.(*model.MapValue)
	evaluator := model.NewCompiledEvaluator()
	evaluator.Environment = tc.mapFieldStringValueOrEmpty(dyn.ID, eval, "environment")
	env, err := tc.newEnv(evaluator.Environment, ctmpl)
	if err != nil {
		// report any environment creation errors.
		envName, _ := eval.GetField("environment")
		tc.reportErrorAtID(envName.Ref.ID, err.Error())
		return nil, nil
	}
	terms, found := eval.GetField("terms")
	productionsEnv := env
	if found {
		productionsEnv, err = tc.compileTerms(terms.Ref, env, evaluator)
		if err != nil {
			tc.reportErrorAtID(terms.Ref.ID, err.Error())
			return nil, nil
		}
	}
	return evaluator, productionsEnv
}

func (tc *templateCompiler) compileTerms(dyn *model.DynValue,
	env *cel.Env, ceval *model.CompiledEvaluator) (*cel.Env, error) {
	terms := dyn.Value.(*model.MapValue)
	termMap := make(map[string]*model.CompiledTerm)
	var termDecls []*exprpb.Decl
	for _, t := range terms.Fields {
		_, found := termMap[t.Name]
		if found {
			tc.reportErrorAtID(t.ID, "term redefinition error")
			continue
		}
		termEnv, err := env.Extend(cel.Declarations(termDecls...))
		if err != nil {
			tc.reportErrorAtID(t.ID, err.Error())
			continue
		}
		termAst := tc.compileExpr(t.Ref, termEnv, true)
		if termAst == nil {
			continue
		}
		term := model.NewCompiledTerm(t.Name, termAst)
		for _, varName := range getVars(termAst) {
			input, found := termMap[varName]
			if found {
				term.InputTerms[varName] = input
			}
		}
		termMap[t.Name] = term
		ceval.Terms = append(ceval.Terms, term)
		termDecls = append(termDecls, decls.NewIdent(t.Name, termAst.ResultType(), nil))
	}
	// Return the productions environment which contains all terms and inputs to the template.
	return env.Extend(cel.Declarations(termDecls...))
}

func (tc *templateCompiler) compileExpr(
	dyn *model.DynValue, env *cel.Env, strict bool) *cel.Ast {
	loc, _ := tc.info.LocationByID(dyn.ID)
	switch v := dyn.Value.(type) {
	case model.BoolValue:
		relSrc := tc.src.Relative(strconv.FormatBool(bool(v)), loc.Line(), loc.Column())
		ast, _ := env.CompileSource(relSrc)
		return ast
	case model.DoubleValue:
		relSrc := tc.src.Relative(
			strconv.FormatFloat(float64(v), 'f', -1, 64),
			loc.Line(), loc.Column())
		ast, _ := env.CompileSource(relSrc)
		return ast
	case model.IntValue:
		relSrc := tc.src.Relative(
			strconv.FormatInt(int64(v), 10),
			loc.Line(), loc.Column())
		ast, _ := env.CompileSource(relSrc)
		return ast
	case model.NullValue:
		relSrc := tc.src.Relative("null", loc.Line(), loc.Column())
		ast, _ := env.CompileSource(relSrc)
		return ast
	case model.PlainTextValue:
		relSrc := tc.src.Relative(strconv.Quote(string(v)), loc.Line(), loc.Column())
		ast, iss := env.CompileSource(relSrc)
		if iss.Err() == nil {
			return ast
		}
		tc.reportIssues(iss)
		return nil
	case *model.MultilineStringValue:
		ast := tc.compileExprString(dyn.ID, v.Raw, loc, env, strict)
		if ast != nil || strict {
			return ast
		}
		// non-strict parse which falls back to a plain text literal.
		txt := model.PlainTextValue(v.Value)
		dyn = model.NewDynValue(dyn.ID, txt)
		return tc.compileExpr(dyn, env, true)
	case model.StringValue:
		ast := tc.compileExprString(dyn.ID, string(v), loc, env, strict)
		if ast != nil || strict {
			return ast
		}
		// non-strict parse which falls back to a plain text literal.
		txt := model.PlainTextValue(v)
		dyn = model.NewDynValue(dyn.ID, txt)
		return tc.compileExpr(dyn, env, true)
	case model.UintValue:
		relSrc := tc.src.Relative(
			strconv.FormatUint(uint64(v), 10)+"u",
			loc.Line(), loc.Column())
		ast, iss := env.CompileSource(relSrc)
		if iss.Err() == nil {
			return ast
		}
		tc.reportIssues(iss)
	default:
		// TODO: support bytes, list, map, timestamp
	}
	return nil
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

func (tc *templateCompiler) newEnv(envName string, ctmpl *model.CompiledTemplate) (*cel.Env, error) {
	ruleTypes := ctmpl.RuleTypes
	var env *cel.Env
	if envName == "" {
		return cel.NewEnv(
			ruleTypes.Types(types.NewRegistry()),
			ruleTypes.Declarations(),
		)
	}
	var found bool
	env, found = tc.reg.FindEnv(envName)
	if !found {
		return nil, errors.New("no such environment")
	}
	return env.Extend(
		ruleTypes.Types(env.TypeProvider()),
		ruleTypes.Declarations(),
	)
}

func (tc *templateCompiler) mapFieldStringValueOrEmpty(id int64,
	m *model.MapValue, fieldName string) string {
	field, found := m.GetField(fieldName)
	if !found {
		// do not report an error as a required field should be reported
		// by the schema checking step.
		return ""
	}
	switch v := field.Ref.Value.(type) {
	case model.StringValue:
		return string(v)
	case model.PlainTextValue:
		return string(v)
	case *model.MultilineStringValue:
		return v.Value
	default:
		// report an error.
		tc.reportErrorAtID(id,
			"unexpected field type: field=%s got=%s wanted=%s",
			fieldName, field.Ref.Value.ModelType(), model.StringType)
		return ""
	}
}

func (tc *templateCompiler) checkSchema(dyn *model.DynValue, schema *model.OpenAPISchema) {
	if schema.TypeRef != "" {
		found := false
		typeRef := schema.TypeRef
		schema, found = tc.reg.FindSchema(typeRef)
		if !found {
			tc.reportErrorAtID(dyn.ID, "no such schema: name=%s", typeRef)
			return
		}
	}
	modelType := schema.ModelType()
	valueType := dyn.Value.ModelType()
	if !assignableToType(valueType, modelType) {
		tc.reportErrorAtID(dyn.ID,
			"value not assignable to schema type: value=%s, schema=%s",
			valueType, modelType)
		return
	}
	switch modelType {
	case model.MapType:
		tc.checkMapSchema(dyn, schema)
	case model.ListType:
		tc.checkListSchema(dyn, schema)
	case model.AnyType:
		return
	default:
		tc.checkPrimitiveSchema(dyn, schema)
	}
}

func (tc *templateCompiler) checkPrimitiveSchema(dyn *model.DynValue, schema *model.OpenAPISchema) {
	// Ensure the value matches the schema type and format.
	dyn.Value = tc.convertToType(dyn.Value, schema)

	// Check whether the input value is one of the enumerated types.
	if schema.Enum != nil {
		for _, e := range schema.Enum {
			val := tc.convertToType(e, schema)
			if dyn.Value.Equal(val) {
				return
			}
		}
		tc.reportErrorAtID(dyn.ID,
			"invalid enum value: %s. must be one of: %v",
			dyn.Value, schema.Enum)
	}
}

func (tc *templateCompiler) checkListSchema(dyn *model.DynValue, schema *model.OpenAPISchema) {
	lv := dyn.Value.(*model.ListValue)
	entrySchema := schema.Items
	for _, entry := range lv.Entries {
		tc.checkSchema(entry, entrySchema)
	}
}

func (tc *templateCompiler) checkMapSchema(dyn *model.DynValue, schema *model.OpenAPISchema) {
	// Check whether the configured properties have been declared and if so, whether they
	// schema-check correctly.
	mv := dyn.Value.(*model.MapValue)
	fields := make(map[string]*model.MapField, len(mv.Fields))
	for _, f := range mv.Fields {
		fields[f.Name] = f
		prop, found := schema.FindProperty(f.Name)
		if !found {
			tc.reportErrorAtID(f.ID, "no such property: %s", f.Name)
			continue
		}
		tc.checkSchema(f.Ref, prop)
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
			tc.reportErrorAtID(dyn.ID, "missing required field(s): %s", missing)
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
		field := model.NewMapField(0, prop)
		field.Ref.Value = tc.convertToType(propSchema.DefaultValue, propSchema)
		tc.checkSchema(field.Ref, propSchema)
		mv.AddField(field)
	}
}

func (tc *templateCompiler) convertToType(val interface{}, schema *model.OpenAPISchema) model.ValueNode {
	vn, isValueNode := val.(model.ValueNode)
	if !isValueNode {
		switch v := val.(type) {
		case bool:
			vn = model.BoolValue(v)
		case float32:
			vn = model.DoubleValue(v)
		case float64:
			vn = model.DoubleValue(v)
		case int:
			vn = model.IntValue(v)
		case int32:
			vn = model.IntValue(v)
		case int64:
			vn = model.IntValue(v)
		case string:
			vn = model.StringValue(v)
		default:
			tc.reportError(common.NoLocation,
				"unsupported type value for schema property. value=%v (%T), schema=%v",
				val, val, schema)
		}
	}
	switch schema.ModelType() {
	case model.TimestampType:
		str, ok := vn.(model.StringValue)
		if !ok {
			tc.reportError(common.NoLocation,
				"cannot convert value to timestamp. value=%s (%T)",
				val, val)
			return vn
		}
		t, err := time.Parse(time.RFC3339, string(str))
		if err != nil {
			tc.reportError(common.NoLocation,
				"timestamp must be RFC3339 format. value=%s", vn)
			return vn
		}
		return model.TimestampValue(t)
	case model.BytesType:
		str, ok := vn.(model.StringValue)
		if !ok {
			tc.reportError(common.NoLocation,
				"cannot convert value to bytes. value=%s (%T)",
				val, val)
			return vn
		}
		if schema.Format == "byte" {
			b, err := base64.StdEncoding.DecodeString(string(str))
			if err != nil {
				tc.reportError(common.NoLocation,
					"byte encoding must be base64. value=%s", str)
				return vn
			}
			return model.BytesValue(b)
		}
		b := []byte(string(str))
		return model.BytesValue(b)
	}
	return vn
}

func (tc *templateCompiler) reportIssues(iss *cel.Issues) {
	tc.errors = tc.errors.Append(iss.Errors())
}

func (tc *templateCompiler) reportError(loc common.Location, msg string, args ...interface{}) {
	tc.errors.ReportError(loc, msg, args...)
}

func (tc *templateCompiler) reportErrorAtID(id int64, msg string, args ...interface{}) {
	loc, found := tc.info.LocationByID(id)
	if !found {
		loc = common.NoLocation
	}
	tc.errors.ReportError(loc, msg, args...)
}

func assignableToType(valType, schemaType string) bool {
	if valType == schemaType || schemaType == model.AnyType {
		return true
	}
	if valType == model.StringType &&
		(schemaType == model.BytesType || schemaType == model.TimestampType) {
		return true
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
