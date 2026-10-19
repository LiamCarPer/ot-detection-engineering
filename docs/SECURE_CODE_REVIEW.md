# Secure code review checklist

Use this for any change that touches a trust boundary: a decoder, the collector,
the ingest service, a workflow, the dependency set, or the AI triage path. It is
deliberately short enough to run on every such pull request.

## Input and trust boundaries

- [ ] Every new input has a defined trust level and a size/shape limit.
- [ ] Parsing is bounds-checked; malformed input fails the input, not the process.
- [ ] Untrusted strings are not interpolated into a query, a shell, or a prompt
      without an explicit boundary.
- [ ] JSON/YAML input is validated against a schema before use.

## Authentication, authorization and abuse

- [ ] New endpoints authenticate, and compare secrets in constant time.
- [ ] Requests are rate-limited and body-capped.
- [ ] Errors do not leak stack traces, paths, tokens or internal identifiers.
- [ ] Logging records the decision (accept/reject, triage verdict) without
      recording the secret or the raw credential.

## Dependencies and supply chain

- [ ] New dependencies are necessary, pinned, and pass SCA.
- [ ] Workflow `uses:` entries are pinned to a commit SHA.
- [ ] Generated artifacts remain covered by `deploy/manifest.json`.
- [ ] No secret, token or key is added to code, fixtures or workflow files.

## AI-specific (when the change touches the triage path)

- [ ] Model output is treated as untrusted: schema-validated and never executed.
- [ ] The model has no tools and cannot change a rule or suppress an alert.
- [ ] Attacker-controlled log fields are isolated from the instruction boundary.
- [ ] A human-review flag is mandatory on every triage result.
- [ ] The adversarial prompt suite covers the new behaviour.

## Verification

- [ ] `make security-preflight` passes.
- [ ] The relevant security CI job is green.
- [ ] A security regression test was added for a fixed defect.
