// Copyright 2019 Google LLC
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

package policy

import (
	"io/ioutil"

	"github.com/google/cel-go/common"
	"gopkg.in/yaml.v3"
)

type file struct {
	common.Source
	fileType fileType
}

type fileType int

const (
	// EvaluatorFile is the policy evaluator file type.
	EvaluatorFile fileType = iota + 1

	// InstanceFile is the policy instance file type.
	InstanceFile

	// TemplateFile is the policy template file type.
	TemplateFile
)

func readFile(location string) (*file, error) {
	content, err := ioutil.ReadFile(location)
	if err != nil {
		return nil, err
	}
	return newFile(string(content), location), nil
}

func newFile(content, location string) *file {
	return &file{
		Source: common.NewStringSource(content, location),
	}
}

func (f *file) newLocalExpr(content string, line, col int) *localExpr {
	return &localExpr{
		Source:   f.Source,
		localSrc: common.NewStringSource(content, f.Source.Description()),
		absLoc:   common.NewLocation(line, col),
	}
}

func (f *file) unmarshalYaml(out interface{}) error {
	return yaml.Unmarshal([]byte(f.Content()), out)
}

type localExpr struct {
	common.Source
	localSrc common.Source
	absLoc   common.Location
}

func (e *localExpr) Location() common.Location {
	return e.absLoc
}

func (e *localExpr) Content() string {
	return e.localSrc.Content()
}

func (e *localExpr) NewLocation(line, col int) common.Location {
	localLoc := common.NewLocation(line, col)
	relOffset, found := e.localSrc.LocationOffset(localLoc)
	if !found {
		return common.NoLocation
	}
	offset, _ := e.Source.LocationOffset(e.absLoc)
	absLoc, _ := e.Source.OffsetLocation(offset + relOffset)
	return absLoc
}

func (e *localExpr) OffsetLocation(offset int32) (common.Location, bool) {
	absOffset, _ := e.Source.LocationOffset(e.absLoc)
	return e.Source.OffsetLocation(absOffset + offset)
}
