# Threat model

The threat model is **code**: [`metadata/threat-model.yaml`](../metadata/threat-model.yaml)
lists the assets, trust boundaries and threats, and
[`metadata/security-controls.yaml`](../metadata/security-controls.yaml) maps each
threat to the controls that mitigate it and the evidence that proves they exist.
`coverage/security_coverage.py` turns the two into a coverage report, and
`tests/test_security_governance.py` refuses an orphaned threat, a control with no
threat, a duplicate id, or an implemented control whose evidence is missing.

## Method

STRIDE for the systems threats (spoofing, tampering, repudiation, information
disclosure, denial of service, elevation of privilege), OWASP's LLM Top 10 for
the AI triage path, and LINDDUN in the privacy review of telemetry that reaches a
model. Each threat carries an abuse case phrased as the attacker's action, not as
a control, so the model describes the adversary rather than the mitigation.

## Trust boundaries

```
 sensor / pcap ──▶ decoder ──▶ collector ──▶ contract ──▶ detections
                     ▲              ▲
                     │              └── untrusted telemetry
             untrusted frames

 client ──▶ ingest API ──▶ (telemetry) ──▶ store
              ▲
              └── untrusted HTTP

 log fields ──▶ prompt builder ──▶ LLM ──▶ schema-validated triage
                    ▲
                    └── attacker-controlled strings

 actions / deps / images ──▶ CI ──▶ signed bundle
```

## Highest-risk threats

1. **A malformed frame crashes a decoder (T-001/T-002).** The decoders read
   attacker-controlled bytes at the network edge; a panic is loss of visibility.
   Mitigated by bounds-checked parsing, `forbid(unsafe_code)`, overflow checks,
   truncation/mutation tests, and (planned) continuous fuzzing.
2. **A compromised dependency or action (T-003/T-004).** The tool has a large
   Python/Rust/GitHub-Actions surface. Mitigated by pinning, Dependabot, SHA-pinned
   actions, and (planned) SCA and workflow analysis.
3. **Prompt injection on the triage path (T-009).** Log fields are attacker text.
   The model must never see instructions as authoritative, its output must be
   schema-validated and never executed, it gets no tools, and a human confirms
   every verdict.
4. **Detection evasion (T-012).** The product is the detection content; an
   adversary who changes one field should not become invisible. Evasion testing
   measures that directly.

## Residual risk

Threats whose only controls are `planned` are listed in the generated security
coverage report. They are accepted for now and tracked, not assumed handled. The
main residual areas are continuous SCA, artifact signing, the ingest API's
authentication and rate limiting, and the AI triage controls — all scheduled in
the security workstream.

## Maintaining the model

Add a threat when a new trust boundary or asset appears; add a control when a
threat gets a mitigation; put the evidence path in the control and make it exist.
The governance test fails otherwise, which is the point.
