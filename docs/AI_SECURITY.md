# AI security

The repository has one AI feature — assisted triage of an alert — and uses AI
assistance to develop itself. Both are in scope here.

## Design stance: the model is untrusted

The triage endpoint in [`services/ingest/`](../services/ingest/) treats the model
like any other untrusted component:

- **The prompt is data, not a conversation.** Only an allowlisted, length-bounded,
  control-character-stripped view of the event reaches the prompt, wrapped in an
  explicit `<telemetry>` boundary; the system message says the block is untrusted
  and must not be followed as instructions.
- **The output is schema-validated.** A strict schema with `additionalProperties:
  false` and `requires_human_review: true`; anything else is rejected with `502`.
- **The output is never executed.** It is a verdict and a short rationale; no
  query, command or tool call is run from model output.
- **No tools.** The model cannot change a rule, an allowlist or an alert.
- **Human review is mandatory.** Every triage result carries the flag; nothing
  auto-closes or auto-suppresses.
- **The provider is pluggable and pinned.** The default is a deterministic,
  offline stub, so CI needs no key and no network. A real provider implements the
  same protocol and passes the same validation.

## OWASP LLM Top 10 mapping

| Risk | Controls | Status |
| :--- | :--- | :--- |
| LLM01 Prompt injection | C-019 adversarial suite, data boundary, structured-only classification | met |
| LLM02 Insecure output handling | C-020 strict schema, never executed | met |
| LLM03 Training data poisoning | Not applicable — no training; provider supply chain covered by C-004/C-005 | n/a |
| LLM04 Model denial of service | C-013 input caps, request limits | met |
| LLM05 Supply chain | C-004 pinned deps, C-005 SCA (planned), C-007 hashes (planned) | partial |
| LLM06 Sensitive information disclosure | C-019 allowlisted prompt, C-024 audit without secrets | met |
| LLM07 Insecure plugin design | C-021 no tools or plugins | met |
| LLM08 Excessive agency | C-021 no tools, human review | met |
| LLM09 Overreliance | C-021 mandatory human review | met |
| LLM10 Model theft | Not applicable — no model weights are hosted | n/a |

The adversarial suite is
[`tests/test_ingest_ai_security.py`](../tests/test_ingest_ai_security.py): it
injects instructions through event fields, returns malicious provider output, and
asserts the verdict, the rationale and the schema hold.

## AI-assisted development policy

AI tools may assist with code, tests and documentation, under these rules:

1. **A human owns every change.** Generated code is reviewed like any other and
   must pass the same gates; no autonomous merge.
2. **No secrets or customer data in prompts.** Telemetry used in examples is the
   committed, synthetic lab data.
3. **Provenance and licence.** Generated code is checked for copied licence
   text; dependencies are pinned and scanned.
4. **Tests before trust.** Generated behaviour gets an example test and, where it
   parses untrusted input, a property or fuzz test.
5. **Disclose when asked.** The project can say which parts were AI-assisted; the
   security properties are demonstrated by tests, not by the authoring method.

## Residual risk

- CI exercises the stub provider, not a live model, so prompt-injection tests
  prove the boundary and the validation, not a specific model's behaviour. A real
  deployment must run the same suite against the chosen provider.
- The endpoint has no model-output logging beyond the verdict and model id, by
  design; debugging a real provider may need a redacted, opt-in trace.
