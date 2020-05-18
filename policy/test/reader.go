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

package test

import (
	"fmt"
	"io/ioutil"
	"sort"
	"strings"

	"github.com/google/cel-policy-templates-go/policy/model"
)

type Case struct {
	ID   string
	Kind string
	In   *model.Source
	Out  string
	Err  string
}

func NewReader(rootDir string) *reader {
	return &reader{rootDir: rootDir}
}

type reader struct {
	rootDir string
}

func (r *reader) ReadCases(phase string) ([]*Case, error) {
	files, err := ioutil.ReadDir(r.rootDir)
	if err != nil {
		return nil, err
	}
	var testCases []*Case
	for i := 0; i < len(files); i++ {
		file := files[i]
		testName := file.Name()
		if !file.IsDir() {
			return nil, fmt.Errorf("file is not a directory: %s", testName)
		}
		testDir := fmt.Sprintf("%s/%s", r.rootDir, testName)
		testFiles, err := ioutil.ReadDir(testDir)
		if err != nil {
			return nil, err
		}
		suffixOut := fmt.Sprintf("%s.out", phase)
		suffixErr := fmt.Sprintf("%s.err", phase)
		for _, tf := range testFiles {
			tfName := tf.Name()
			if strings.HasSuffix(tfName, suffixOut) {
				baseName := tfName[0 : len(tfName)-len(suffixOut)-1]
				inName := testDir + "/" + baseName + ".yaml"
				outName := testDir + "/" + tfName
				kind := baseName
				if ind := strings.Index(baseName, "."); ind >= 0 {
					kind = baseName[0:ind]
				}
				in := r.Read(inName)
				out := r.Read(outName).Content()
				testCases = append(
					testCases,
					&Case{
						ID:   testName + "/" + baseName,
						Kind: kind,
						In:   in,
						Out:  out,
					},
				)
			}
			if strings.HasSuffix(tfName, suffixErr) {
				baseName := tfName[0 : len(tfName)-len(suffixErr)-1]
				inName := testDir + "/" + baseName + ".yaml"
				errName := testDir + "/" + tfName
				kind := baseName
				if ind := strings.Index(baseName, "."); ind >= 0 {
					kind = baseName[0:ind]
				}
				in := r.Read(inName)
				err := r.Read(errName).Content()
				testCases = append(
					testCases,
					&Case{
						ID:   testName + "/" + baseName,
						Kind: kind,
						In:   in,
						Err:  err,
					},
				)
			}
		}
	}
	sort.SliceStable(testCases, func(i, j int) bool {
		if testCases[i].Kind == testCases[j].Kind {
			return false
		}
		return testCases[i].Kind == "template"
	})
	return testCases, nil
}

func (r *reader) Read(fileName string) *model.Source {
	tmplBytes, err := ioutil.ReadFile(fileName)
	if err != nil {
		panic(err)
	}
	return model.ByteSource(tmplBytes, fileName)
}
