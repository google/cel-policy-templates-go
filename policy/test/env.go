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
	Decls = cel.Declarations(
		decls.NewIdent("destination.ip", decls.String, nil),
		decls.NewIdent("origin.ip", decls.String, nil),
		decls.NewIdent("request.auth.claims", decls.NewMapType(decls.String, decls.Dyn), nil),
		decls.NewIdent("request.time", decls.Timestamp, nil),
		decls.NewIdent("resource.name", decls.String, nil),
		decls.NewIdent("resource.type", decls.String, nil),
		decls.NewIdent("resource.labels", decls.NewMapType(decls.String, decls.String), nil),
		decls.NewFunction("locationCode",
			decls.NewOverload("location_code_string",
				[]*exprpb.Type{decls.String},
				decls.String,
			),
		),
	)

	Funcs = []*functions.Overload{
		&functions.Overload{
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
