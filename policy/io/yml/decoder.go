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

	"gopkg.in/yaml.v3"

	"github.com/google/cel-go/common"
	"github.com/google/cel-policy-templates-go/policy/config"
)

// DecodeInstance decodes a YAML source object to a config.Instance.
//
// The decoding step relies on the use of YAML tags to determine the type of each element.
// Specially, the tags used must align with the ones produced by the Go YAML v3 library.
//
// Errors in the decoding will result in a nil config.Instance.
func DecodeInstance(src *config.Source) (*config.Instance, *common.Errors) {
	// Common objects for decoding an instance.
	errs := common.NewErrors(src)
	info := config.NewSourceInfo(src)
	inst := &config.Instance{SourceInfo: info}
	builder := newInstanceBuilder(inst)
	dec := newDecoder(info, errs)
	dec.decodeYaml(src, builder)
	// If there are errors, return a nil instance and the error set.
	if len(errs.GetErrors()) != 0 {
		return nil, errs
	}
	// Otherwise, return the instance.
	return inst, errs
}

// DecodeTemplate decodes a YAML source object to a config.Template.
//
// The decoding step relies on the use of YAML tags to determine the type of each element.
// Specially, the tags used must align with the ones produced by the Go YAML v3 library.
//
// Errors in the decoding will result in a nil config.Template.
func DecodeTemplate(src *config.Source) (*config.Template, *common.Errors) {
	errs := common.NewErrors(src)
	info := config.NewSourceInfo(src)
	tmpl := &config.Template{SourceInfo: info}
	builder := newTemplateBuilder(tmpl)
	dec := newDecoder(info, errs)
	dec.decodeYaml(src, builder)
	// If there are errors, return a nil instance and the error set.
	if len(errs.GetErrors()) != 0 {
		return nil, errs
	}
	// Otherwise, return the instance.
	return tmpl, errs
}

func (d *decoder) decodeYaml(src *config.Source, builder objRef) {
	// Parse yaml representation from the source to an object model.
	var docNode yaml.Node
	err := sourceToYaml(src, &docNode)
	if err != nil {
		d.errs.ReportError(common.NoLocation, err.Error())
		return
	}
	d.collectMetadata(1, &docNode)
	d.decode(docNode.Content[0], builder)
}

func sourceToYaml(src *config.Source, docNode *yaml.Node) error {
	err := yaml.Unmarshal([]byte(src.Content()), docNode)
	if err != nil {
		return err
	}
	if docNode.Kind != yaml.DocumentNode {
		return fmt.Errorf("got yaml node of kind %v, wanted mapping node", docNode.Kind)
	}
	return nil
}

func newDecoder(info *config.SourceInfo, errs *common.Errors) *decoder {
	return &decoder{
		info: info,
		errs: errs,
	}
}

type decoder struct {
	id   int64
	info *config.SourceInfo
	errs *common.Errors
}

func (d *decoder) nextID() int64 {
	d.id++
	return d.id
}

func (d *decoder) collectMetadata(id int64, node *yaml.Node) {
	var comments []*config.Comment
	if txt := node.HeadComment; txt != "" {
		comments = append(comments, config.NewHeadComment(txt))
	}
	if txt := node.LineComment; txt != "" {
		comments = append(comments, config.NewLineComment(txt))
	}
	if txt := node.FootComment; txt != "" {
		comments = append(comments, config.NewFootComment(txt))
	}
	if len(comments) > 0 {
		d.info.Comments[id] = comments
	}
	offset := int32(0)
	if node.Line > 1 {
		offset = d.info.LineOffsets[node.Line-2]
	}
	d.info.Offsets[id] = offset + int32(node.Column) - 1
}

func (d *decoder) decode(node *yaml.Node, ref objRef) {
	id := d.nextID()
	d.collectMetadata(id, node)
	ref.id(id)
	celType, found := yamlTypes[node.LongTag()]
	if !found {
		d.reportErrorAtID(id, "unsupported yaml type: %s", node.LongTag())
		return
	}
	switch celType {
	case "list":
		d.decodeSeq(node, ref)
	case "map":
		d.decodeMap(node, ref)
	default:
		d.decodePrimitive(node, ref)
	}
}

func (d *decoder) decodePrimitive(node *yaml.Node, ref objRef) {
	var err error
	celType := yamlTypes[node.LongTag()]
	switch celType {
	case "bool":
		ref.assign(node.Value == "true")
	case "double":
		val, convErr := strconv.ParseFloat(node.Value, 64)
		if convErr != nil {
			d.reportErrorAtID(d.id, convErr.Error())
		} else {
			err = ref.assign(val)
		}
	case "int":
		var val interface{} = nil
		val, convErr := strconv.ParseInt(node.Value, 10, 64)
		if convErr != nil {
			var convErr2 error
			val, convErr2 = strconv.ParseUint(node.Value, 10, 64)
			if convErr2 != nil {
				d.reportErrorAtID(d.id, convErr.Error())
			} else {
				err = ref.assign(val)
			}
		} else {
			err = ref.assign(val)
		}
	case "null":
		err = ref.assign(config.Null)
	case "string":
		err = ref.assign(node.Value)
	default:
		d.reportErrorAtID(d.id, "unsupported cel type: %s", celType)
	}
	if err != nil {
		d.reportErrorAtID(d.id, err.Error())
	}
}

func (d *decoder) decodeSeq(node *yaml.Node, ref objRef) {
	for i, val := range node.Content {
		elem, err := ref.propAt(i)
		if err != nil {
			d.reportErrorAtID(d.id, err.Error())
		} else {
			d.decode(val, elem)
		}
	}
}

func (d *decoder) decodeMap(node *yaml.Node, ref objRef) {
	for i := 0; i < len(node.Content); i += 2 {
		key := node.Content[i]
		id := d.nextID()
		d.collectMetadata(id, key)

		val := node.Content[i+1]
		keyType, found := yamlTypes[key.LongTag()]
		if !found || keyType != "string" {
			d.reportErrorAtID(id, "invalid map key type: %v", key.LongTag())
			continue
		}
		prop := key.Value
		propRef, err := ref.prop(id, prop)
		if err != nil {
			d.reportErrorAtID(id, err.Error())
			continue
		}
		d.decode(val, propRef)
	}
}

func (d *decoder) reportErrorAtID(id int64, format string, args ...interface{}) {
	loc, found := d.info.LocationByID(id)
	if !found {
		loc = common.NoLocation
	}
	d.errs.ReportError(loc, format, args...)
}

var (
	// yamlTypes map of the long tag names supported by the Go YAML v3 library.
	yamlTypes = map[string]string{
		"tag:yaml.org,2002:bool":  "bool",
		"tag:yaml.org,2002:null":  "null",
		"tag:yaml.org,2002:str":   "string",
		"tag:yaml.org,2002:int":   "int",
		"tag:yaml.org,2002:float": "double",
		"tag:yaml.org,2002:seq":   "list",
		"tag:yaml.org,2002:map":   "map",
	}
)
