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
	"encoding/binary"
	"fmt"
	"hash/maphash"
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
	errs := tc.errors.GetErrors()
	if len(errs) != 0 {
		return nil, tc.errors
	}

	ctmpl := model.NewCompiledTemplate()
	tc.compileTemplate(dyn, ctmpl)
	errs = tc.errors.GetErrors()
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
	ctmpl.APIVersion = tc.mapFieldStringValue(m, "apiVersion")
	ctmpl.Description = tc.mapFieldStringValueOrEmpty(m, "description")
	ctmpl.Kind = tc.mapFieldStringValue(m, "kind")
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
		// TODO: build the type registry
		ctmpl.RuleTypes = model.NewRuleTypes(ctmpl.Kind, schema)
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
	// TODO:
}

func (tc *templateCompiler) compileOpenAPISchema(dyn *model.DynValue,
	schema *model.OpenAPISchema) {
	m, ok := dyn.Value.(*model.MapValue)
	if !ok {
		// report error
		return
	}
	schema.Title = tc.mapFieldStringValueOrEmpty(m, "title")
	schema.Description = tc.mapFieldStringValueOrEmpty(m, "description")
	schema.Type = tc.mapFieldStringValueOrEmpty(m, "type")
	schema.TypeRef = tc.mapFieldStringValueOrEmpty(m, "$ref")
	schema.Format = tc.mapFieldStringValueOrEmpty(m, "format")
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
			// report error, continue without error
			meta = model.NewMapValue()
		}
		for _, mf := range meta.Fields {
			val, ok := mf.Ref.Value.(model.StringValue)
			if ok {
				schema.Metadata[mf.Name] = string(val)
			} else {
				// report error
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
		// the validator block has not be configured.
		return
	}
	validator, prodsEnv, err := tc.buildProductionsEnv(val, ctmpl)
	if err != nil {
		// report the error
		return
	}
	prods, found := val.GetField("productions")
	if found {
		tc.compileValidatorOutputDecisions(prods.Ref, prodsEnv, validator)
	}
	ctmpl.Validator = validator
}

func (tc *templateCompiler) compileValidatorOutputDecisions(prods *model.DynValue,
	env *cel.Env, ceval *model.CompiledEvaluator) {
	productions := prods.Value.(*model.ListValue)
	rules := make([]*model.CompiledProduction, len(productions.Entries))
	for i, p := range productions.Entries {
		prod := p.Value.(*model.MapValue)
		match, _ := prod.GetField("match")
		matchAst := tc.compileExpr(match.Ref, env, true)
		rule := model.NewCompiledProduction(matchAst)
		// TODO: Add more structure checking here. For now, build a JSON object.
		msg, found := prod.GetField("message")
		if found {
			tc.compileExpr(msg.Ref, env, false)
			// create a json encoder for model.DynValue
		}
		det, found := prod.GetField("details")
		if found {
			tc.compileExpr(det.Ref, env, false)
			// create a json encoder for model.DynValue
		}
		outDec := model.NewCompiledDecision("policy.invalid")
		rule.Decisions = append(rule.Decisions, outDec)
		rules[i] = rule
	}
}

func (tc *templateCompiler) compileEvaluator(dyn *model.DynValue,
	ctmpl *model.CompiledTemplate) {
	eval := dyn.Value.(*model.MapValue)
	if len(eval.Fields) == 0 {
		// the validator block has not be configured.
		return
	}
	evaluator, _, err := tc.buildProductionsEnv(eval, ctmpl)
	if err != nil {
		// report the error
		return
	}
	_, found := eval.GetField("productions")
	if found {
		// tc.compileEvaluatorOutputDecisions(prods.Ref, rulesEnv, evaluator)
	}
	ctmpl.Evaluator = evaluator
}

func (tc *templateCompiler) buildProductionsEnv(eval *model.MapValue,
	ctmpl *model.CompiledTemplate) (*model.CompiledEvaluator, *cel.Env, error) {
	evaluator := model.NewCompiledEvaluator()
	evaluator.Environment = tc.mapFieldStringValueOrEmpty(eval, "environment")
	env, err := tc.newEnv(evaluator.Environment, ctmpl)
	if err != nil {
		// report any environment creation errors.
		return nil, nil, err
	}
	terms, found := eval.GetField("terms")
	productionsEnv := env
	if found {
		productionsEnv, err = tc.compileTerms(terms.Ref, env, evaluator)
		if err != nil {
			// report the term compilation environment
			return nil, nil, err
		}
	}
	return evaluator, productionsEnv, nil
}

func (tc *templateCompiler) compileTerms(dyn *model.DynValue,
	env *cel.Env, ceval *model.CompiledEvaluator) (*cel.Env, error) {
	terms := dyn.Value.(*model.MapValue)
	var termMap map[string]*model.CompiledTerm
	var termDecls []*exprpb.Decl
	for _, t := range terms.Fields {
		_, found := termMap[t.Name]
		if found {
			// report term redeclaration error
			continue
		}
		termEnv, err := env.Extend(cel.Declarations(termDecls...))
		if err != nil {
			// report error
			continue
		}
		termAst := tc.compileExpr(t.Ref, termEnv, true)
		term := model.NewCompiledTerm(t.Name, termAst)
		for _, varName := range getVars(termAst) {
			input, found := termMap[varName]
			if found {
				term.InputTerms[varName] = input
			}
		}
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
	case model.PlainTextValue:
		relSrc := tc.src.Relative(strconv.Quote(string(v)), loc.Line(), loc.Column())
		ast, iss := env.CompileSource(relSrc)
		if iss.Err() == nil {
			return ast
		}
		tc.reportIssues(iss)
		return nil
	case model.StringValue:
		relSrc := tc.src.Relative(string(v), loc.Line(), loc.Column())
		ast, iss := env.CompileSource(relSrc)
		if iss.Err() == nil {
			return ast
		}
		if strict {
			tc.reportIssues(iss)
			return nil
		}
		// non-strict parse which falls back to a plain text literal.
		txt := model.PlainTextValue(v)
		dyn = model.NewDynValue(dyn.ID, txt)
		return tc.compileExpr(dyn, env, true)
	case *model.ListValue:
	case *model.MapValue:
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
		// report error
		return nil, fmt.Errorf("no such environment: %s", envName)
	}
	return env.Extend(
		ruleTypes.Types(env.TypeProvider()),
		ruleTypes.Declarations(),
	)
}

func (tc *templateCompiler) mapFieldStringValue(m *model.MapValue, fieldName string) string {
	field, found := m.GetField(fieldName)
	if !found {
		// report an error.
		return ""
	}
	val, ok := field.Ref.Value.(model.StringValue)
	if !ok {
		// report an error.
		return ""
	}
	return string(val)
}

func (tc *templateCompiler) mapFieldStringValueOrEmpty(m *model.MapValue,
	fieldName string) string {
	field, found := m.GetField(fieldName)
	if !found {
		// do not report an error
		return ""
	}
	val, ok := field.Ref.Value.(model.StringValue)
	if !ok {
		// report an error.
		return ""
	}
	return string(val)
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
			tc.reportErrorAtID(dyn.ID, "missing required properties: %s", missing)
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
		mv.Fields = append(mv.Fields, field)
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
	tc.errors.Append(iss.Errors())
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

func hashSchema(s *model.OpenAPISchema) uint64 {
	var hsh maphash.Hash
	hsh.WriteString(s.ModelType())
	switch s.ModelType() {
	case model.ListType:
		nestedHash := hashSchema(s.Items)
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, nestedHash)
		hsh.WriteByte(255)
		hsh.Write(b)
	case model.MapType:
		for field, nested := range s.Properties {
			hsh.WriteByte(255)
			hsh.WriteString(field)
			nestedHash := hashSchema(nested)
			b := make([]byte, 8)
			binary.LittleEndian.PutUint64(b, nestedHash)
			hsh.WriteByte(255)
			hsh.Write(b)
		}
		if s.AdditionalProperties != nil {
			nestedHash := hashSchema(s.AdditionalProperties)
			b := make([]byte, 8)
			binary.LittleEndian.PutUint64(b, nestedHash)
			hsh.WriteByte(255)
			hsh.Write(b)
		}
	}
	return hsh.Sum64()
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
