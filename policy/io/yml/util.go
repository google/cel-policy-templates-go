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
	"github.com/google/cel-policy-templates-go/policy/model"
)

// YamlToInstance decodes a YAML source to a model.Instance.
//
// If errors are encountered during decode, they are returned via the CEL Errors object.
func YamlToInstance(src *model.Source) (*model.Instance, *common.Errors) {
	return DecodeInstance(src)
}

// InstanceToYaml encodes a model.Instance to a YAML source string.
func InstanceToYaml(instance *model.Instance) *model.Source {
	yml := EncodeInstance(instance)
	return model.StringSource(yml, instance.SourceInfo.Description)
}
