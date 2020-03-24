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

package io

import (
	"io/ioutil"

	"github.com/google/cel-policy-templates-go/policy/model"
)

// ReadFile reads a model.Source from a file location.
//
// Errors in reading the source will result in an error and a nil source.
func ReadFile(location string) (*model.Source, error) {
	content, err := ioutil.ReadFile(location)
	if err != nil {
		return nil, err
	}
	return model.ByteSource(content, location), nil
}
