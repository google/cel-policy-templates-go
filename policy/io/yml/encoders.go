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

package yml

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/google/cel-policy-templates-go/policy/config"
)

// EncodeInstance serializes a config.Instance to a string according to an optional set of encoding
// options.
//
// The instance does not necessarily need to be well-formed in order to be encoded.
func EncodeInstance(instance *config.Instance, opts ...EncodeOption) string {
	if instance == nil {
		return ""
	}
	enc := &encoder{
		indents:   [][]string{},
		lineStart: true,
		comments:  instance.SourceInfo.Comments,
	}
	for _, opt := range opts {
		enc = opt(enc)
	}
	return enc.writeInstance(instance).String()
}

func EncodeTemplate(template *config.Template, opts ...EncodeOption) string {
	if template == nil {
		return ""
	}
	enc := &encoder{
		indents:   [][]string{},
		lineStart: true,
		comments:  template.SourceInfo.Comments,
	}
	for _, opt := range opts {
		enc = opt(enc)
	}
	return enc.writeTemplate(template).String()
}

// EncodeOption describes a functional argument for configuring the behavior of the encoder.
type EncodeOption func(*encoder) *encoder

// RenderDebugIDs modifies the encoding to print out source element ids into the encoded string.
func RenderDebugIDs(enc *encoder) *encoder {
	enc.renderIDs = true
	return enc
}

type encoder struct {
	buf       strings.Builder
	indents   [][]string
	lineStart bool
	renderIDs bool
	comments  map[int64][]*config.Comment
}

// String implements the fmt.Stringer interface.
func (enc *encoder) String() string {
	return enc.buf.String()
}

func (enc *encoder) writeTemplate(tmpl *config.Template) *encoder {
	enc.renderID(tmpl.ID)
	if enc.writeComment(tmpl.ID, config.HeadComment) {
		enc.eol().eol()
	}
	return enc.
		writeField(tmpl.APIVersion).
		writeField(tmpl.Kind).
		writeField(tmpl.Metadata).
		writeField(tmpl.Description).
		writeField(tmpl.RuleSchema).
		writeValidator(tmpl.Validator).
		writeEvaluator(tmpl.Evaluator).
		writeFootComment(tmpl.ID)
}

func (enc *encoder) writeValidator(val *config.Validator) *encoder {
	if val == nil {
		return enc
	}
	return enc.
		writeFieldName(val.ID, "validator").eol().
		indent().
		writeField(val.Environment).
		writeField(val.Terms).
		writeValidatorProductions(val.Productions).
		dedent().
		writeFootComment(val.ID)
}

func (enc *encoder) writeValidatorProductions(p *config.ValidatorProductions) *encoder {
	if p == nil {
		return enc
	}
	enc.writeFieldName(p.ID, "productions").eol().
		indent().
		indentList()
	for _, prod := range p.Values {
		// TODO: start struct position will be wrong with poorly-formed input
		enc.writeField(prod.Match).startStruct().
			writeField(prod.Message).
			writeField(prod.Details).
			endStruct()
	}
	return enc.
		dedent().
		dedent().
		writeFootComment(p.ID)
}

func (enc *encoder) writeEvaluator(eval *config.Evaluator) *encoder {
	if eval == nil {
		return enc
	}
	return enc.
		writeFieldName(eval.ID, "evaluator").eol().
		indent().
		writeField(eval.Environment).
		writeField(eval.Terms).
		writeEvaluatorProductions(eval.Productions).
		dedent().
		writeFootComment(eval.ID)
}

func (enc *encoder) writeEvaluatorProductions(p *config.EvaluatorProductions) *encoder {
	if p == nil {
		return enc
	}
	enc.writeFieldName(p.ID, "productions").eol().
		indent().
		indentList()
	for _, prod := range p.Values {
		// TODO: start struct position will be wrong with poorly-formed input
		enc.writeField(prod.Match).startStruct()
		if prod.OutputDecision != nil {
			out := prod.OutputDecision
			enc.writeField(out.Decision).
				writeField(out.Reference).
				writeField(out.Output)
		}
		if prod.OutputDecisions != nil {
			outs := prod.OutputDecisions
			enc.writeFieldName(outs.ID, "decisions").eol().
				indent().
				indentList()
			for _, outDec := range outs.Values {
				enc.writeField(outDec.Decision).startStruct().
					writeField(outDec.Reference).
					writeField(outDec.Output).
					endStruct()
			}
			enc.dedent().
				dedent().
				writeFootComment(outs.ID)
		}
		enc.endStruct()
	}
	return enc.
		dedent().
		dedent().
		writeFootComment(p.ID)
}

func (enc *encoder) writeInstance(inst *config.Instance) *encoder {
	enc.renderID(inst.ID)
	if enc.writeComment(inst.ID, config.HeadComment) {
		enc.eol().eol()
	}
	return enc.
		writeField(inst.APIVersion).
		writeField(inst.Kind).
		writeField(inst.Metadata).
		writeField(inst.Description).
		writeSelector(inst.Selector).
		writeField(inst.Rules).
		writeFootComment(inst.ID)
}

func (enc *encoder) writeSelector(sel *config.Selector) *encoder {
	if sel == nil {
		return enc
	}
	enc.writeFieldName(sel.ID, "selector").eol().
		indent()
	if sel.MatchLabels != nil {
		enc.writeFieldName(sel.MatchLabels.ID, "matchLabels").eol().
			indent()
		for _, m := range sel.MatchLabels.Matchers {
			if m.Key != nil {
				keyName := m.Key.Value.(config.StringValue)
				enc.writeFieldName(m.Key.ID, string(keyName))
				enc.writeFieldValue(m.Value)
				enc.writeFootComment(m.Key.ID)
			}
		}
		enc.dedent()
	}
	if sel.MatchExpressions != nil {
		enc.writeFieldName(sel.MatchExpressions.ID, "matchExpressions").eol().
			indent()
		for _, m := range sel.MatchExpressions.Matchers {
			if m.Key != nil {
				enc.writeHeadComment(m.Key.ID)
				enc.write("- {")
				enc.write("key: ").writeInlineValue(m.Key)
			}
			if m.Operator != nil {
				if m.Key == nil {
					enc.writeHeadComment(m.Operator.ID)
					enc.write("- {")
				} else {
					enc.write(", ")
				}
				enc.write("operator: ").writeInlineValue(m.Operator)
			}
			if m.Values != nil {
				if m.Key == nil && m.Operator == nil {
					enc.writeHeadComment(m.Values.ID)
					enc.write("- {")
				} else {
					enc.write(", ")
				}
				enc.write("values: [")
				lv := m.Values.Value.(*config.ListValue)
				for i, v := range lv.Entries {
					enc.writeInlineValue(v)
					if i < len(lv.Entries)-1 {
						enc.write(", ")
					}
				}
				enc.write("]")
			}
			if m.Key != nil || m.Operator != nil || m.Values != nil {
				enc.write("}").eol()
			}
		}
		enc.dedent()
	}
	return enc.dedent()
}

func (enc *encoder) writeStruct(sv *config.StructValue) *encoder {
	inList := enc.inList()
	for i, f := range sv.Fields {
		enc.writeField(f)
		if i == 0 && inList {
			enc.startStruct()
		}
	}
	if len(sv.Fields) > 0 && inList {
		enc.endStruct()
	}
	return enc
}

func (enc *encoder) writeList(lv *config.ListValue) *encoder {
	enc.indentList()
	for _, e := range lv.Entries {
		enc.writeValue(e)
	}
	return enc.dedent()
}

func (enc *encoder) writeNestedValue(v *config.DynValue) *encoder {
	return enc.writeValueInternal(v, true, true)
}

func (enc *encoder) writeInlineValue(v *config.DynValue) *encoder {
	return enc.writeValueInternal(v, false, false)
}

func (enc *encoder) writeValue(v *config.DynValue) *encoder {
	return enc.writeValueInternal(v, false, true)
}

func (enc *encoder) writeValueInternal(v *config.DynValue, eolStart, eolEnd bool) *encoder {
	if v == nil {
		return enc.eol()
	}
	enc.renderID(v.ID).writeHeadComment(v.ID)
	isPrimitive := false
	switch dyn := v.Value.(type) {
	case *config.ListValue:
		if eolStart {
			enc.eol()
			enc.indent()
		}
		enc.writeList(dyn)
		if eolStart {
			enc.dedent()
		}
	case *config.StructValue:
		if eolStart {
			enc.eol()
			enc.indent()
		}
		enc.writeStruct(dyn)
		if eolStart {
			enc.dedent()
		}
	case config.StringValue:
		isPrimitive = true
		str := strconv.Quote(string(dyn))
		enc.write(str).writeLineComment(v.ID)
	case config.NullValue:
		isPrimitive = true
		enc.write("null").writeLineComment(v.ID)
	default:
		isPrimitive = true
		enc.write(fmt.Sprintf("%v", dyn)).writeLineComment(v.ID)
	}
	if isPrimitive && eolEnd {
		enc.eol()
	}
	enc.writeFootComment(v.ID)
	return enc
}

func (enc *encoder) writeField(field *config.StructField) *encoder {
	if field == nil {
		return enc
	}
	return enc.
		writeFieldName(field.ID, field.Name).
		writeFieldValue(field.Ref).
		writeFootComment(field.ID)
}

func (enc *encoder) writeFieldName(id int64, field string) *encoder {
	return enc.
		renderID(id).
		writeHeadComment(id).
		write(field).write(":").writeLineComment(id)
}

func (enc *encoder) writeFieldValue(val *config.DynValue) *encoder {
	switch val.Value.(type) {
	case *config.ListValue, *config.StructValue:
		enc.writeNestedValue(val)
	default:
		enc.write(" ").writeValue(val)
	}
	return enc
}

func (enc *encoder) writeHeadComment(id int64) *encoder {
	if enc.writeComment(id, config.HeadComment) {
		enc.eol()
	}
	return enc
}

func (enc *encoder) writeLineComment(id int64) *encoder {
	enc.writeComment(id, config.LineComment)
	return enc
}

func (enc *encoder) writeFootComment(id int64) *encoder {
	if enc.writeComment(id, config.FootComment) {
		enc.eol().eol()
	}
	return enc
}

func (enc *encoder) writeComment(id int64, style config.CommentStyle) bool {
	cmts, hasComments := enc.comments[id]
	if !hasComments {
		return false
	}
	hasComments = false
	for _, cmt := range cmts {
		if cmt.Style == style {
			if style == config.LineComment {
				enc.write(" ")
			}
			lines := strings.Split(cmt.Text, "\n")
			for i, ln := range lines {
				enc.write(ln)
				if i < len(lines)-1 {
					enc.eol()
				}
			}
			hasComments = true
		}
	}
	return hasComments
}

func (enc *encoder) indent() *encoder {
	curr := []string{}
	if len(enc.indents) > 0 {
		curr = enc.indents[len(enc.indents)-1]
	}
	next := make([]string, len(curr)+1, len(curr)+1)
	for i := 0; i < len(next); i++ {
		next[i] = "  "
	}
	enc.indents = append(enc.indents, next)
	return enc
}

func (enc *encoder) indentList() *encoder {
	curr := []string{}
	if len(enc.indents) > 0 {
		curr = enc.indents[len(enc.indents)-1]
	}
	next := make([]string, len(curr)+1, len(curr)+1)
	for i := 0; i < len(curr); i++ {
		next[i] = "  "
	}
	next[len(curr)] = "- "
	enc.indents = append(enc.indents, next)
	return enc
}

func (enc *encoder) startStruct() *encoder {
	curr := []string{}
	if len(enc.indents) > 0 {
		curr = enc.indents[len(enc.indents)-1]
	}
	next := make([]string, len(curr), len(curr))
	for i := 0; i < len(curr); i++ {
		next[i] = "  "
	}
	enc.indents = append(enc.indents, next)
	return enc
}

func (enc *encoder) endStruct() *encoder {
	enc.indents = enc.indents[:len(enc.indents)-1]
	return enc
}

func (enc *encoder) renderID(id int64) *encoder {
	if enc.renderIDs && id != 0 {
		enc.write(fmt.Sprintf("%d~", id))
	}
	return enc
}

func (enc *encoder) dedent() *encoder {
	enc.indents = enc.indents[:len(enc.indents)-1]
	return enc
}

func (enc *encoder) inList() bool {
	curr := enc.indents[len(enc.indents)-1]
	return curr[len(curr)-1] == "- "
}

func (enc *encoder) write(str string) *encoder {
	if enc.lineStart && len(enc.indents) != 0 {
		curr := enc.indents[len(enc.indents)-1]
		for _, indent := range curr {
			enc.buf.WriteString(indent)
		}
		enc.lineStart = false
	}
	enc.buf.WriteString(str)
	return enc
}

func (enc *encoder) eol() *encoder {
	enc.buf.WriteString("\n")
	enc.lineStart = true
	return enc
}
