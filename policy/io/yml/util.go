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
	"github.com/google/cel-go/common"
	"github.com/google/cel-policy-templates-go/policy/config"
)

// YamlToInstance decodes a YAML source to a config.Instance.
//
// If errors are encountered during decode, they are returned via the CEL Errors object.
func YamlToInstance(src *config.Source) (*config.Instance, *common.Errors) {
	return DecodeInstance(src)
}

// InstanceToYaml encodes a config.Instance to a YAML source string.
func InstanceToYaml(instance *config.Instance) *config.Source {
	yml := EncodeInstance(instance)
	return config.StringSource(yml, instance.SourceInfo.Description)
}

// YamlToTemplate decodes a YAML source to a config.Template.
//
// If errors are encountered during decode, they are returned via the CEL Errors object.
func YamlToTemplate(src *config.Source) (*config.Template, *common.Errors) {
	return DecodeTemplate(src)
}

// TemplateToYaml encodes a config.Instance to a YAML source string.
func TemplateToYaml(template *config.Template) *config.Source {
	yml := EncodeTemplate(template)
	return config.StringSource(yml, template.SourceInfo.Description)
}
