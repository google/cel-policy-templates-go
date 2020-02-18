# CEL Policy Templates

CEL Policy Templates provide a framework for defining new policy types and
evaluating policy instances against many different requests. 

There are many more policy admins, people who know the details of the data used
to configure policy, than there are policy architects, people who know how the
data is evaluated under the covers. This project, much like OPA Gatekeeper is
aimed at making it easier for both the architect and admin to create new policy
types and policies to match their business needs.

## Core Concepts

There are three key components: templates, instances, and evaluators.

### Templates

Templates define the shape of the policy. Templates are written in YAML and use
Open API Schema v3 terminology. Templates are the interface between policy
architects and policy admins.

### Instances

Instances are written by policy admins. Instances are collectively applied to
and enforced against inputs. The instance content is validated against the
template definition. 

### Evaluators

Evaluators are written by policy architects. An evaluator refers to a template
and is written as though it will evaluate a single instance of the template
against a single evaluation context. The expressions within the evaluator
are written in CEL and are checked for syntactic correctness, cycles, and
type-agreement.

### Environments

Environments specify an Engine's configuration, and are critical to Evaluator
validation. An environment declares the variables and functions available to
an Evaluator.

## Why CEL Policy Templates?

CEL Policy Templates are based on the Common Expression Language (CEL). CEL
is fast, portable, and supports both extension and subsetting. The flexibility
of CEL makes it possible to limit the compute and memory impact of a given
expression. CEL is non-Turing complete and its performance makes it a suitable
choice for all kinds of policies such as admission control, access control,
and networking policies. Individual CEL expressions evaluate on the order of
nanos to microseconds.

OPA Gatekeeper is another alternative to consider which offers rich audit and
analysis tools, but at the expense of performance, typically on the order of
milliseconds. OPA offers support for Kubernetes, Istio, and Envoy as plugins.
This is a great choice for admission control. CEL on the other hand is a core
component of the Google Cloud IAM, Istio Mixer, and Envoy security policies
where it is used in latency critical, high throughput operations.

_Disclaimer_: This is not an officially supported Google product
