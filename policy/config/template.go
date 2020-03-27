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

package config

// Template defines the structure of a generic policy template.
//
// Each template instantiation defines a unique template 'kind' which describes the definition,
// validation, and evaulation contract for all policy instances of that kind.
//
// Templates may optionally declare an Instance rule schema which allows for policy admins to
// customize the evaluation logic. The template may also define validation and evaluation logic
// which is applied at the Instance 'rule'-level. The validation logic runs at policy instance
// admission time. The evaluation logic runs at request evaluation time.
//
// If a template does not declare a schema, a default 'empty' rule is evaluated whenever the
// Instance is applicable to the current evaluation as determined by the Instance's selector.
type Template struct {
	// APIVersion indicates the version of the Template's schema.
	// Type: string
	APIVersion *StructField

	// Kind identifies the schema id used to validate the Policy Template.
	// Type: string
	Kind *StructField

	// Metadata contains information which uniquely identifies the instance.
	// The metadata struct must contain a 'name' or 'uid' property. A 'namespace' property may
	// optionally be set, otherwise the namespace is 'default'.
	// Type: struct
	Metadata *StructField

	// Description is a human-readable string describing the behavior of the Policy Template.
	// Type: string
	Description *StructField

	// RuleSchema declares the type for an Instance rule. Optional.
	//
	// Protobuf message descriptors and Open API v3 Schema definitions are sufficient to describe
	// the complex types that can map to CEL primitives.
	// Type: struct
	RuleSchema *StructField

	// Validator defines the validation logic to be applied at the Instance rule-level.
	//
	// The RuleSchema is used to validate the rule structure, but a validator is intended to check
	// the rule content.
	Validator *Validator

	// Evaluator defines the evaluation logic to be applied at the Instance rule-level.
	Evaluator *Evaluator

	// ID specifying the source element id fo the object within a config.Source.
	ID int64

	// SourceInfo contains metadata about source positions, line offsets, and comments.
	// The object is useful for debug purposes, but is not required to be available at evaluation
	// time.
	SourceInfo *SourceInfo
}

// Validator specifies logic used to check the content of an Instance rule for correctness.
//
// A validator is a specialized Evaluator which is applied at the time an Instance is configured.
// An Instance is well formed if it conforms to the overall instance schema and if each of its
// rules adheres to the Template's rule schema and validator logic.
//
// The logic for a validator is written using CEL expressions. The variables and functions
// available to these expressions are declared in the named Environment string.
//
// Terms are local variables composed from CEL expressions based on the Environment. The purpose
// of a term is to reduce repeated expressions within match statements in the production rules.
//
// Productions are a list of CEL predicates which, if true, will produce a violation with the
// message and details stated directly beneath.
type Validator struct {
	ID          int64
	Environment *StructField
	Terms       *StructField
	Productions *ValidatorProductions
}

// ValidatorProductions contain a list of production rules that are used to validate the content
// of the policy instance rules on a per-rule basis. The object also contains a numeric reference
// to its parse location
type ValidatorProductions struct {
	ID     int64
	Values []*ValidatorProduction
}

// ValidatorProduction declares a match predicate which indicates whether the error message and
// details are emitted with the validation failure message.
type ValidatorProduction struct {
	// Match predicate written in CEL.
	// Type: CEL expression.
	Match *StructField

	// Error message expression.
	// Type: CEL expression.
	Message *StructField

	// Details structured object. Optional.
	// Type: CEL struct.
	Details *StructField
}

// Evaluator defines the core conditional decision logic to be applied to a Template Instance on a
// per-rule basis.
//
// Evaluators use CEL expressions to define their logic, where the expression may refer to any
// variable or function declared in the named Environment.
//
// Note, Environments are declared as a part of the application rather than as a file-based input
// into the evaluation engine.
type Evaluator struct {
	ID          int64
	Environment *StructField
	Terms       *StructField
	Productions *EvaluatorProductions
}

// EvaluatorProductions contains a list of productions (match, output decision) to evaluate against
// the Instance rules on a per-rule basis.
//
// The object also contains a reference to its parse location id.
type EvaluatorProductions struct {
	ID     int64
	Values []*EvaluatorProduction
}

// EvaluatorProduction contains a CEL-based match predicate, which if true, will result in at
// least one OutputDecision emitted to the runtime.
//
// The output decision value will be aggregated by the runtime according to the aggregation
// behavior defined for the decision.
type EvaluatorProduction struct {
	// Match is a CEL-based predicate, which if true, will result in at least one output decision.
	// Type: CEL Expression.
	Match *StructField

	// OutputDecision is the singleton decision to emit.
	//
	// If the OutputDecision is set, then the OuputDecisions must not be set.
	OutputDecision *OutputDecision

	// OutputDecisions contain a list of related decisions to emit.
	//
	// If the OutputDecisions field is set, the OutputDecision must not be set.
	OutputDecisions *OutputDecisions
}

// OutputDecisions contains a list of OutputDecision values associated with the evaluator
// production as well as a reference to its parse location id.
type OutputDecisions struct {
	ID     int64
	Values []*OutputDecision
}

// OutputDecision refers to a decision by name or by reference with a possibly structured output.
type OutputDecision struct {
	// Decision name as a qualified identifier name.
	// Type: string
	Decision *StructField

	// Reference to a decision, meaning the value of the expression on the right hand side is the
	// decision name.
	// Type: CEL expression.
	Reference *StructField

	// Output is a dynamically typed object to emit as the value of the decision. The type of the
	// object must agree with the decision type.
	// Type: CEL expression.
	//
	// Note, decision types are defined outside the template as part of the application
	// environment.
	Output *StructField
}
