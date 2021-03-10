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

// Package yml defines tools for parsing and encoding CPT sources written in YAML.
package yml

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/cel-policy-templates-go/policy/model"

	"gopkg.in/yaml.v3"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common"
	"github.com/google/cel-go/common/types"
)

// Parse decodes a YAML source object to a model.ParsedValue.
//
// The decoding step relies on the use of YAML tags to determine the type of each element.
// Specially, the tags used must align with the ones produced by the Go YAML v3 library.
//
// Errors in the decoding will result in a nil model.ParsedValue.
func Parse(src *model.Source) (*model.ParsedValue, *cel.Issues) {
	// Common objects for decoding an instance.
	errs := common.NewErrors(src)
	info := model.NewSourceInfo(src)
	inst := &model.ParsedValue{Meta: info}
	builder := newParsedValueBuilder(inst)
	parser := newParser(info, src, errs)
	parser.parseYaml(src, builder)
	// If there are errors, return a nil instance and the error set.
	if len(errs.GetErrors()) != 0 {
		return nil, cel.NewIssues(errs)
	}
	// Otherwise, return the instance.
	return inst, nil
}

func (p *parser) parseYaml(src *model.Source, builder objRef) {
	// Parse yaml representation from the source to an object model.
	var docNode yaml.Node
	err := sourceToYaml(src, &docNode)
	if err != nil {
		p.errs.ReportError(common.NoLocation, err.Error())
		return
	}
	p.collectMetadata(1, &docNode)
	p.parse(docNode.Content[0], builder)
}

func sourceToYaml(src *model.Source, docNode *yaml.Node) error {
	err := yaml.Unmarshal([]byte(src.Content()), docNode)
	if err != nil {
		return err
	}
	if docNode.Kind != yaml.DocumentNode {
		return fmt.Errorf("got yaml node of kind %v, wanted mapping node", docNode.Kind)
	}
	return nil
}

func newParser(info *model.SourceInfo, src *model.Source, errs *common.Errors) *parser {
	return &parser{
		info: info,
		src:  src,
		errs: errs,
	}
}

type parser struct {
	id   int64
	info *model.SourceInfo
	src  *model.Source
	errs *common.Errors
}

func (p *parser) nextID() int64 {
	p.id++
	return p.id
}

func (p *parser) collectMetadata(id int64, node *yaml.Node) {
	var comments []*model.Comment
	if txt := node.HeadComment; txt != "" {
		comments = append(comments, model.NewHeadComment(txt))
	}
	if txt := node.LineComment; txt != "" {
		comments = append(comments, model.NewLineComment(txt))
	}
	if txt := node.FootComment; txt != "" {
		comments = append(comments, model.NewFootComment(txt))
	}
	if len(comments) > 0 {
		p.info.Comments[id] = comments
	}

	line := node.Line
	col := int32(node.Column)
	switch node.Style {
	case yaml.DoubleQuotedStyle, yaml.SingleQuotedStyle:
		col++
	}
	offset := int32(0)
	if line > 1 {
		offset = p.info.LineOffsets[line-2]
	}
	p.info.Offsets[id] = offset + col - 1
}

func (p *parser) parse(node *yaml.Node, ref objRef) {
	id := p.nextID()
	p.collectMetadata(id, node)
	ref.id(id)
	modelType, found := yamlTypes[node.LongTag()]
	if !found {
		p.reportErrorAtID(id, "unsupported yaml type: %s", node.LongTag())
		return
	}
	switch modelType.TypeName() {
	case model.ListType.TypeName():
		ref.initList()
		p.parseList(node, ref)
	case model.MapType.TypeName():
		ref.initMap()
		p.parseMap(node, ref)
	default:
		p.parsePrimitive(node, ref)
	}
	ref.encodeStyle(getEncodeStyle(node.Style))
}

func (p *parser) parsePrimitive(node *yaml.Node, ref objRef) {
	var err error
	modelType := yamlTypes[node.LongTag()]
	switch modelType {
	case model.BoolType:
		ref.assign(node.Value == "true")
	case model.DoubleType:
		val, convErr := strconv.ParseFloat(node.Value, 64)
		if convErr != nil {
			p.reportErrorAtID(p.id, convErr.Error())
		} else {
			err = ref.assign(val)
		}
	case model.PlainTextType:
		err = ref.assign(model.PlainTextValue(node.Value))
	case model.IntType:
		var val interface{}
		val, convErr := strconv.ParseInt(node.Value, 10, 64)
		if convErr != nil {
			var convErr2 error
			val, convErr2 = strconv.ParseUint(node.Value, 10, 64)
			if convErr2 != nil {
				p.reportErrorAtID(p.id, convErr.Error())
			} else {
				err = ref.assign(val)
			}
		} else {
			err = ref.assign(val)
		}
	case model.NullType:
		err = ref.assign(types.NullValue)
	case model.StringType:
		if node.Style == yaml.FoldedStyle ||
			node.Style == yaml.LiteralStyle {
			col := node.Column
			line := node.Line
			txt, found := p.src.Snippet(line)
			indent := ""
			for len(indent) < col-1 {
				indent += " "
			}
			var raw strings.Builder
			for found && strings.HasPrefix(txt, indent) {
				line++
				raw.WriteString(txt)
				txt, found = p.src.Snippet(line)
				if found && strings.HasPrefix(txt, indent) {
					raw.WriteString("\n")
				}
			}
			offset := p.info.Offsets[p.id]
			offset = offset - (int32(node.Column) - 1)
			p.info.Offsets[p.id] = offset
			multi := &model.MultilineStringValue{
				Value: node.Value,
				Raw:   raw.String(),
			}
			err = ref.assign(multi)
		} else {
			err = ref.assign(node.Value)
		}
	case model.TimestampType:
		val, convErr := time.Parse(time.RFC3339, node.Value)
		if convErr != nil {
			p.reportErrorAtID(p.id, convErr.Error())
		} else {
			err = ref.assign(val)
		}
	default:
		p.reportErrorAtID(p.id, "unsupported cel type: %v", modelType)
	}
	if err != nil {
		p.reportErrorAtID(p.id, err.Error())
	}
}

func (p *parser) parseList(node *yaml.Node, ref objRef) {
	for i, val := range node.Content {
		elem, err := ref.entry(i)
		if err != nil {
			p.reportErrorAtID(p.id, err.Error())
		} else {
			p.parse(val, elem)
		}
	}
}

func (p *parser) parseMap(node *yaml.Node, ref objRef) {
	for i := 0; i < len(node.Content); i += 2 {
		key := node.Content[i]
		id := p.nextID()
		p.collectMetadata(id, key)
		keyType, found := yamlTypes[key.LongTag()]
		if !found || keyType != model.StringType {
			p.reportErrorAtID(id, "unsupported map key type: %v", key.LongTag())
			continue
		}
		prop := key.Value
		propRef, err := ref.field(id, prop)
		if err != nil {
			p.reportErrorAtID(id, err.Error())
			continue
		}
		val := node.Content[i+1]
		if val.Style == yaml.FoldedStyle || val.Style == yaml.LiteralStyle {
			val.Line++
			val.Column = key.Column + 2
		}
		p.parse(val, propRef)
	}
}

func (p *parser) reportErrorAtID(id int64, format string, args ...interface{}) {
	loc, found := p.info.LocationByID(id)
	if !found {
		loc = common.NoLocation
	}
	p.errs.ReportError(loc, format, args...)
}

var (
	// yamlTypes map of the long tag names supported by the Go YAML v3 library.
	yamlTypes = map[string]*model.DeclType{
		"!txt":                        model.PlainTextType,
		"tag:yaml.org,2002:bool":      model.BoolType,
		"tag:yaml.org,2002:null":      model.NullType,
		"tag:yaml.org,2002:str":       model.StringType,
		"tag:yaml.org,2002:int":       model.IntType,
		"tag:yaml.org,2002:float":     model.DoubleType,
		"tag:yaml.org,2002:seq":       model.ListType,
		"tag:yaml.org,2002:map":       model.MapType,
		"tag:yaml.org,2002:timestamp": model.TimestampType,
	}
)

func getEncodeStyle(style yaml.Style) model.EncodeStyle {
	switch style {
	case yaml.FlowStyle:
		return model.FlowValueStyle
	case yaml.FoldedStyle:
		return model.FoldedValueStyle
	case yaml.LiteralStyle:
		return model.LiteralStyle
	default:
		return model.BlockValueStyle
	}
}
