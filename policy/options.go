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
	"github.com/google/cel-policy-templates-go/policy/model"
	"github.com/google/cel-policy-templates-go/policy/runtime"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/interpreter"
)

// EngineOption is a functional option for configuring the policy engine.
type EngineOption func(*Engine) (*Engine, error)

// Selector functions take a compiled representation of a policy instance 'selector' and the input
// argument set to determine whether the policy instance is applicable to the current evaluation
// context.
type Selector func(model.Selector, interpreter.Activation) bool

// Selectors is a functional option which may be configured to select a subset of policy instances
// which are applicable to the current evaluation context.
func Selectors(selectors ...Selector) EngineOption {
	return func(e *Engine) (*Engine, error) {
		e.selectors = selectors
		return e, nil
	}
}

// StandardExprEnv configures the CEL expression environment to be used as the basis for all
// other environment derivations within templates.
func StandardExprEnv(exprEnv *cel.Env) EngineOption {
	return func(e *Engine) (*Engine, error) {
		e.Registry = model.NewRegistry(exprEnv)
		// Set the default environment
		err := e.Registry.SetEnv("", model.NewEnv(""))
		if err != nil {
			return nil, err
		}
		return e, nil
	}
}

// RangeLimit sets the range limit supported by the compilation and runtime components.
func RangeLimit(limit int) EngineOption {
	return func(e *Engine) (*Engine, error) {
		e.limits.RangeLimit = limit
		return e, nil
	}
}

// EvaluatorTermLimit sets the evaluator term limit supported by the compilation and runtime
// components.
func EvaluatorTermLimit(limit int) EngineOption {
	return func(e *Engine) (*Engine, error) {
		e.limits.EvaluatorTermLimit = limit
		return e, nil
	}
}

// EvaluatorProductionLimit set the evaluator production limit supported by the compilation and
// runtime components.
func EvaluatorProductionLimit(limit int) EngineOption {
	return func(e *Engine) (*Engine, error) {
		e.limits.EvaluatorProductionLimit = limit
		return e, nil
	}
}

// EvaluatorDecisionLimit set the evaluator decision limit within a single production supported by
// the compilation and runtime components.
func EvaluatorDecisionLimit(limit int) EngineOption {
	return func(e *Engine) (*Engine, error) {
		e.limits.EvaluatorDecisionLimit = limit
		return e, nil
	}
}

// ValidatorTermLimit sets the validator term limit supported by the compilation and runtime
// components.
func ValidatorTermLimit(limit int) EngineOption {
	return func(e *Engine) (*Engine, error) {
		e.limits.ValidatorTermLimit = limit
		return e, nil
	}
}

// ValidatorProductionLimit set the validator production limit supported by the compilation and
// runtime components.
func ValidatorProductionLimit(limit int) EngineOption {
	return func(e *Engine) (*Engine, error) {
		e.limits.ValidatorProductionLimit = limit
		return e, nil
	}
}

// RuleLimit sets the rule limit within a policy instance supported by the compilation and runtime
// components.
func RuleLimit(limit int) EngineOption {
	return func(e *Engine) (*Engine, error) {
		e.limits.RuleLimit = limit
		return e, nil
	}
}

// EvaluatorExprCostLimit sets the evaluator expression cost limit supported by the compilation and
// runtime components.
func EvaluatorExprCostLimit(limit int) EngineOption {
	return func(e *Engine) (*Engine, error) {
		e.limits.EvaluatorExprCostLimit = limit
		return e, nil
	}
}

// RuntimeTemplateOptions collects a set of runtime specific options to be configured on runtime
// templates.
func RuntimeTemplateOptions(rtOpts ...runtime.TemplateOption) EngineOption {
	return func(e *Engine) (*Engine, error) {
		e.rtOpts = append(e.rtOpts, rtOpts...)
		return e, nil
	}
}
