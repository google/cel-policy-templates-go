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
	"time"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-policy-templates-go/policy/model"
)

// Encode serializes a model.ParsedValue to a string according to an optional set of encoding
// options.
//
// The ParsedValue does not necessarily need to be well-formed in order to be encoded.
func Encode(pv *model.ParsedValue, opts ...EncodeOption) string {
	if pv == nil {
		return ""
	}
	enc := &encoder{
		indents:   [][]string{},
		lineStart: true,
		meta:      pv.Meta,
	}
	for _, opt := range opts {
		enc = opt(enc)
	}
	enc.renderID(pv.ID)
	if enc.writeComment(pv.ID, model.HeadComment) {
		enc.eol().eol()
	}
	for _, f := range pv.Value.Fields {
		enc.writeField(f).maybeEOL()
	}
	return enc.writeFootComment(pv.ID).String()
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
	meta      model.SourceMetadata
}

// String implements the fmt.Stringer interface.
func (enc *encoder) String() string {
	return enc.buf.String()
}

func (enc *encoder) writeFields(fields []*model.Field) *encoder {
	inList := enc.inList()
	for i, f := range fields {
		enc.writeField(f).maybeEOL()
		if i == 0 && inList {
			enc.startMap()
		}
	}
	if len(fields) > 0 && inList {
		enc.endMap()
	}
	return enc
}

func (enc *encoder) writeList(lv *model.ListValue) *encoder {
	enc.indentList()
	for _, e := range lv.Entries {
		enc.writeValue(e).maybeEOL()
	}
	return enc.dedent()
}

func (enc *encoder) writeNestedValue(v *model.DynValue) *encoder {
	return enc.writeValueInternal(v, true)
}

func (enc *encoder) writeInlineValue(v *model.DynValue) *encoder {
	switch val := v.Value().(type) {
	case *model.MapValue:
		enc.renderID(v.ID).writeHeadComment(v.ID)
		enc.write("{")
		for i, f := range val.Fields {
			enc.writeInlineField(f)
			if i < len(val.Fields)-1 {
				enc.write(", ")
			}
		}
		return enc.write("}").
			writeLineComment(v.ID).
			writeFootComment(v.ID)
	case *model.ListValue:
		enc.renderID(v.ID).writeHeadComment(v.ID)
		enc.write("[")
		for i, e := range val.Entries {
			enc.writeInlineValue(e)
			if i < len(val.Entries)-1 {
				enc.write(", ")
			}
		}
		return enc.write("]").
			writeLineComment(v.ID).
			writeFootComment(v.ID)
	default:
		return enc.writeValueInternal(v, false)
	}
}

func (enc *encoder) writeValue(v *model.DynValue) *encoder {
	if v.EncodeStyle == model.FlowValueStyle {
		return enc.writeInlineValue(v)
	}
	return enc.writeValueInternal(v, false)
}

func (enc *encoder) writeValueInternal(v *model.DynValue, eol bool) *encoder {
	enc.renderID(v.ID).writeHeadComment(v.ID)
	isPrimitive := false
	switch dyn := v.Value().(type) {
	case *model.ListValue:
		if eol {
			enc.eol()
			enc.indent()
		}
		enc.writeList(dyn)
		if eol {
			enc.dedent()
		}
	case *model.MapValue:
		if eol {
			enc.eol()
			enc.indent()
		}
		enc.writeFields(dyn.Fields)
		if eol {
			enc.dedent()
		}
	case *model.ObjectValue:
		if eol {
			enc.eol()
			enc.indent()
		}
		enc.writeFields(dyn.Fields)
		if eol {
			enc.dedent()
		}
	case model.PlainTextValue:
		isPrimitive = true
		str := strconv.Quote(string(dyn))
		enc.write("!txt ").write(str).writeLineComment(v.ID)
	case *model.MultilineStringValue:
		isPrimitive = true
		if v.EncodeStyle == model.FoldedValueStyle {
			enc.write(">").writeLineComment(v.ID).write("\n")
		}
		if v.EncodeStyle == model.LiteralStyle {
			enc.write("|").writeLineComment(v.ID).write("\n")
		}
		enc.write(dyn.Raw).writeLineComment(v.ID)
	case string:
		isPrimitive = true
		str := strconv.Quote(dyn)
		enc.write(str).writeLineComment(v.ID)
	case time.Time:
		isPrimitive = true
		enc.write(fmt.Sprintf("%q", dyn.Format(time.RFC3339))).writeLineComment(v.ID)
	case types.Null:
		isPrimitive = true
		enc.writeLineComment(v.ID)
	default:
		isPrimitive = true
		enc.write(fmt.Sprintf("%v", dyn)).writeLineComment(v.ID)
	}
	if isPrimitive && eol {
		enc.eol()
	}
	enc.writeFootComment(v.ID)
	return enc
}

func (enc *encoder) writeInlineField(field *model.Field) *encoder {
	return enc.writeFieldName(field.ID, field.Name).write(" ").
		writeInlineValue(field.Ref)
}

func (enc *encoder) writeField(field *model.Field) *encoder {
	enc.writeFieldName(field.ID, field.Name)
	if field.Ref.EncodeStyle == model.FlowValueStyle {
		enc.writeInlineValue(field.Ref).maybeEOL()
	} else {
		enc.writeFieldValue(field.Ref).maybeEOL()
	}
	// TODO: handle folded style.
	return enc.writeFootComment(field.ID)
}

func (enc *encoder) writeFieldName(id int64, field string) *encoder {
	return enc.
		renderID(id).
		writeHeadComment(id).
		write(field).write(":").writeLineComment(id)
}

func (enc *encoder) writeFieldValue(val *model.DynValue) *encoder {
	switch val.Value().(type) {
	case *model.ListValue, *model.MapValue:
		enc.writeNestedValue(val)
	default:
		enc.write(" ").writeValue(val)
	}
	return enc
}

func (enc *encoder) writeHeadComment(id int64) *encoder {
	if enc.writeComment(id, model.HeadComment) {
		enc.eol()
	}
	return enc
}

func (enc *encoder) writeLineComment(id int64) *encoder {
	enc.writeComment(id, model.LineComment)
	return enc
}

func (enc *encoder) writeFootComment(id int64) *encoder {
	if enc.writeComment(id, model.FootComment) {
		enc.eol().eol()
	}
	return enc
}

func (enc *encoder) writeComment(id int64, style model.CommentStyle) bool {
	cmts, hasComments := enc.meta.CommentsByID(id)
	if !hasComments {
		return false
	}
	hasComments = false
	for _, cmt := range cmts {
		if cmt.Style == style {
			if style == model.LineComment {
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

func (enc *encoder) startMap() *encoder {
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

func (enc *encoder) endMap() *encoder {
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
	if enc.lineStart {
		if len(enc.indents) != 0 {
			curr := enc.indents[len(enc.indents)-1]
			for _, indent := range curr {
				enc.buf.WriteString(indent)
			}
		}
		enc.lineStart = false
	}
	enc.buf.WriteString(str)
	return enc
}

func (enc *encoder) maybeEOL() *encoder {
	if enc.lineStart {
		return enc
	}
	return enc.eol()
}

func (enc *encoder) eol() *encoder {
	enc.buf.WriteString("\n")
	enc.lineStart = true
	return enc
}
