# Testing

Test inputs are designed to be shared across the parse, compile, and evaluate
phases of templates and instances. Adding new tests should require no
additional code to validate the parsing and compilation steps, and only minimal
code to configure a new set of expected inputs and outputs for evaluation.

## Structure

Tests are grouped into folders whose names are indicative of the behavior under
test. The tests themselves need not be fully formed instances or templates, but
must at least parse.

The general folder layout is as follows:

```
testdata
    |
    |--- <test_name>
              |---  <kind>.yaml
              |---  <kind>.<phase>.out
              |---  <kind>.<phase>.err
```

The `kind` value is either `instance` or `template`.
The `phase` value is either `parse` or `compile`.
Positive test cases have the `.out` suffix.
Negative test cases have the `.err` suffix.

If a `<kind>.yaml` file does not have a corresponding `<kind>.<phase>.<suffix>`
file, the file is not included in the case set for the `phase`.

## Using Testdata

To consume `testdata` within a test, the simplest way to consume the test cases
is to use the `test.NewReader(relDir)` with the `ReadCases` method to obtain a
list of test cases, sorted templates before instances, which are applicable to
a given `phase` of execution.

```go
// Test Reader configured to read from the relative location of the testdata
// folder.
// Example folder: policy/parser/yml
tr := test.NewReader("../../testdata")
```

## Extension

The current set of variables and functions supported within the test inputs
include all of the `test.Decls` and `test.Funcs`. If additional variables and
functions are neded for a test, please add them to the `test/env.go` file.

## Future Work

In the future, the tests should be usable within an `eval` phase. In order for
evaluation to work, there needs to be a way to serialize a CEL environment, as
well as the the test inputs and outputs. The CEL conformance tests will be used
as inspiration for end to end eval tests.
