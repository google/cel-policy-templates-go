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
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter/functions"

	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

var (
	// Decls represent the standard variables and functions available for testing templates.
	Decls = cel.Declarations(
		decls.NewVar("destination.ip", decls.String),
		decls.NewVar("origin.ip", decls.String),
		decls.NewVar("request.auth.claims", decls.NewMapType(decls.String, decls.Dyn)),
		decls.NewVar("request.time", decls.Timestamp),
		decls.NewVar("resource.name", decls.String),
		decls.NewVar("resource.type", decls.String),
		decls.NewVar("resource.labels", decls.NewMapType(decls.String, decls.String)),
		decls.NewFunction("locationCode",
			decls.NewOverload("location_code_string",
				[]*exprpb.Type{decls.String},
				decls.String,
			),
		),
	)

	// Funcs are the custom function implementations used within templates.
	Funcs = []*functions.Overload{
		{
			Operator: "location_code_string",
			Unary: func(ip ref.Val) ref.Val {
				switch ip.(types.String) {
				case types.String("10.0.0.1"):
					return types.String("us")

				case types.String("10.0.0.2"):
					return types.String("de")
				default:
					return types.String("ir")
				}
			},
		},
	}
)
