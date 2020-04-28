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

	"github.com/golang/protobuf/proto"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common"
	"github.com/google/cel-go/common/types"

	"github.com/google/cel-policy-templates-go/policy/model"

	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

type Compiler struct {
	reg Registry
}

func (c *Compiler) CompileTemplate(src *model.Source, tmpl *model.ParsedValue) (*model.Template, *common.Errors) {
	tc := &templateCompiler{
		reg:    c.reg,
		src:    src,
		info:   tmpl.Info,
		errors: common.NewErrors(src),
	}
	dyn := model.NewDynValue(tmpl.ID, tmpl.Value)
	tc.checkSchema(dyn, model.TemplateSchema)
	ctmpl := model.NewTemplate()
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

func (tc *templateCompiler) compileTemplate(dyn *model.DynValue, ctmpl *model.Template) {
	m := tc.mapValue(dyn)
	ctmpl.APIVersion = tc.mapFieldStringValueOrEmpty(dyn, "apiVersion")
	ctmpl.Description = tc.mapFieldStringValueOrEmpty(dyn, "description")
	ctmpl.Kind = tc.mapFieldStringValueOrEmpty(dyn, "kind")
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
}

func (tc *templateCompiler) compileValidator(dyn *model.DynValue,
	ctmpl *model.Template) {
	val := tc.mapValue(dyn)
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
	env *cel.Env, ceval *model.Evaluator) {
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
		rule := model.NewProduction(matchAst)
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
		outDec := model.NewDecision()
		outDec.Decision = "policy.invalid"
		outDec.Output = ast
		rule.Decisions = append(rule.Decisions, outDec)
		prodRules[i] = rule
	}
	ceval.Productions = prodRules
}

func (tc *templateCompiler) compileEvaluator(dyn *model.DynValue,
	ctmpl *model.Template) {
	eval := tc.mapValue(dyn)
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
	env *cel.Env, ceval *model.Evaluator) {
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
		rule := model.NewProduction(matchAst)
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
	outDec := model.NewDecision()
	dec, decFound := prod.GetField("decision")
	ref, refFound := prod.GetField("reference")
	out, outFound := prod.GetField("output")
	if !decFound && !refFound && !outFound {
		return nil, false
	}
	if decFound {
		decName := tc.strValue(dec.Ref)
		outDec.Decision = string(decName)
	}
	if refFound {
		outDec.Reference = tc.compileExpr(ref.Ref, env, true)
	}
	if !decFound && !refFound {

	}
	if outFound {
		outDec.Output = tc.compileExpr(out.Ref, env, false)
	} else {

	}
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
	env *cel.Env, ceval *model.Evaluator) (*cel.Env, error) {
	terms := tc.mapValue(dyn)
	termMap := make(map[string]*model.Term)
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
		termType := decls.Error
		termAst := tc.compileExpr(t.Ref, termEnv, true)
		term := model.NewTerm(t.Name, termAst)
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

func (tc *templateCompiler) newEnv(envName string, ctmpl *model.Template) (*cel.Env, error) {
	ruleTypes := ctmpl.RuleTypes
	var env *cel.Env
	if envName == "" {
		if ruleTypes == nil {
			return cel.NewEnv()
		}
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
	if ruleTypes == nil {
		return env, nil
	}
	return env.Extend(
		ruleTypes.Types(env.TypeProvider()),
		ruleTypes.Declarations(),
	)
}

func (tc *templateCompiler) strValue(dyn *model.DynValue) model.StringValue {
	s, ok := dyn.Value.(model.StringValue)
	if ok {
		return s
	}
	tc.reportErrorAtID(dyn.ID, "expected string type, found: %s", dyn.Value.ModelType())
	return model.StringValue("")
}

func (tc *templateCompiler) listValue(dyn *model.DynValue) *model.ListValue {
	l, ok := dyn.Value.(*model.ListValue)
	if ok {
		return l
	}
	tc.reportErrorAtID(dyn.ID, "expected list type, found: %s", dyn.Value.ModelType())
	return model.NewListValue()
}

func (tc *templateCompiler) mapValue(dyn *model.DynValue) *model.MapValue {
	m, ok := dyn.Value.(*model.MapValue)
	if ok {
		return m
	}
	tc.reportErrorAtID(dyn.ID, "expected map type, found: %s", dyn.Value.ModelType())
	return model.NewMapValue()
}

func (tc *templateCompiler) mapFieldStringValueOrEmpty(dyn *model.DynValue,
	fieldName string) string {
	m := tc.mapValue(dyn)
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
		tc.reportErrorAtID(dyn.ID,
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
	lv := tc.listValue(dyn)
	entrySchema := schema.Items
	for _, entry := range lv.Entries {
		tc.checkSchema(entry, entrySchema)
	}
}

func (tc *templateCompiler) checkMapSchema(dyn *model.DynValue, schema *model.OpenAPISchema) {
	// Check whether the configured properties have been declared and if so, whether they
	// schema-check correctly.
	mv := tc.mapValue(dyn)
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
