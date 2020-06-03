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

// Case is a test case for use with parsing, compiling, or evaluating.
type Case struct {
	// ID is a human-readable short-name for the test case.
	ID string

	// Kind is the type of test case this is, either template or instance.
	Kind string

	// In contains a reference to the source under test.
	In *model.Source

	// Out represents the output value expected from the test in a positive case.
	//
	// Note, positive test cases bear the '.out' suffix within testdata folders.
	Out string

	// Err is the error expected from the negative case of the test.
	//
	// Note, negative test cases bear the '.err' suffix within testdata folders.
	Err string
}

// NewReader constructs a new test reader with the relative location of the testdata.
func NewReader(relDir string) *reader {
	return &reader{relDir: relDir}
}

type reader struct {
	relDir string
}

// ReadCases returns a set of test cases which match a given execution phase. The test cases for
// a given folder are sorted such that all templates appear before all instances. This way the
// successful compilation of a template may be used with subsequent tests for instances.
//
// The 'phase' value may be either 'parse' or 'compile'.
//
// TODO: support 'eval' phase via ReadCases.
func (r *reader) ReadCases(phase string) ([]*Case, error) {
	files, err := ioutil.ReadDir(r.relDir)
	if err != nil {
		return nil, err
	}
	var testCases []*Case
	for i := 0; i < len(files); i++ {
		file := files[i]
		testName := file.Name()
		if testName == "README.md" {
			continue
		}
		if !file.IsDir() {
			return nil, fmt.Errorf("file is not a directory: %s", testName)
		}
		testDir := fmt.Sprintf("%s/%s", r.relDir, testName)
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
				in, _ := r.Read(inName)
				out, _ := r.Read(outName)
				testCases = append(
					testCases,
					&Case{
						ID:   testName + "/" + baseName,
						Kind: kind,
						In:   in,
						Out:  out.Content(),
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
				in, _ := r.Read(inName)
				err, _ := r.Read(errName)
				testCases = append(
					testCases,
					&Case{
						ID:   testName + "/" + baseName,
						Kind: kind,
						In:   in,
						Err:  err.Content(),
					},
				)
			}
		}
	}
	sort.SliceStable(testCases, func(i, j int) bool {
		if testCases[i].Kind == testCases[j].Kind {
			return false
		}
		if testCases[i].Kind == "env" {
			return true
		}
		if testCases[j].Kind == "env" {
			return false
		}
		return testCases[i].Kind == "template"
	})
	return testCases, nil
}

// Read returns the Source instance for the given file name.
func (r *reader) Read(fileName string) (*model.Source, bool) {
	tmplBytes, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, false
	}
	return model.ByteSource(tmplBytes, fileName), true
}
