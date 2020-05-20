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

// Package limits defines the set of operational limits which developers may configure to control
// the compute and memory impact of the policies they support.
package limits

// NewLimits returns a Limits object configured with the default limits.
func NewLimits() *Limits {
	return &Limits{}
}

// Limits holds the set of shared limits used to configure different components of CEL policy
// templates.
type Limits struct {
	// RangeLimit limits the number of for-in ranges which may appear within a template evaluator.
	//
	// Note, the number of ranges proportionally increases the polynomial evaluation time of a
	// policy where eval time is on the order of O(n^ranges).
	//
	// Defaults to 0.
	RangeLimit int

	// TODO: Add term, production, and expression size limits
}

