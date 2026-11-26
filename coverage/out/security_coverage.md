# Security Control Coverage

**15 / 17** threats have an implemented control (88.2%); **23 / 29** controls are implemented.

Generated from `metadata/threat-model.yaml` and `metadata/security-controls.yaml` by `coverage/security_coverage.py`.

## Threats

| Threat | Asset | Framework | Implemented controls | Covered |
| :--- | :--- | :--- | :--- | :--- |
| T-001 A malformed protocol frame crashes or corrupts the decoder | decode-path | STRIDE | C-001, C-016 | yes |
| T-002 Hostile input causes resource exhaustion in a parser | decode-path | STRIDE | C-001, C-013 | yes |
| T-003 A dependency or toolchain component is compromised or vulnerable | ci-supply-chain | STRIDE | C-004, C-005, C-006 | yes |
| T-004 A compromised GitHub Action executes with repository credentials | ci-supply-chain | STRIDE | C-008, C-009 | yes |
| T-005 A credential or secret is committed to the repository | ci-supply-chain | STRIDE | C-010, C-011 | yes |
| T-006 A released artifact is substituted after generation | release-bundle | STRIDE | C-012 | yes |
| T-007 An unauthenticated or spoofed client submits telemetry | ingest-api | STRIDE | C-004, C-017 | yes |
| T-008 A client floods the ingest API | ingest-api | STRIDE | C-013, C-018 | yes |
| T-009 Prompt injection through attacker-controlled log fields | ai-triage | OWASP-LLM | C-019, C-022 | yes |
| T-010 Insecure handling of model output | ai-triage | OWASP-LLM | C-020, C-022 | yes |
| T-011 The model is given excessive agency | ai-triage | OWASP-LLM | C-021, C-022 | yes |
| T-012 Attacker traffic evades the committed detections | rule-corpus | STRIDE | none | no |
| T-013 Security-relevant actions are not attributable | ingest-api | STRIDE | C-024 | yes |
| T-014 The service container escapes or runs with excess privilege | ingest-api | STRIDE | none | no |
| T-015 Security requirements and controls drift from the code | rule-corpus | NIST-SSDF | C-003, C-027 | yes |
| T-016 Unreviewed or untested logic regresses | telemetry-pipeline | NIST-SSDF | C-011, C-015, C-028 | yes |
| T-017 A vulnerability is reported with no handling process | release-bundle | NIST-SSDF | C-029 | yes |

## Controls

| Control | Status | Verify | Evidence |
| :--- | :--- | :--- | :--- |
| C-001 Bounds-checked, panic-resistant protocol decoders | implemented | `make rust` | `tools/dnp3-dpi/tests/robustness.rs` |
| C-002 Fuzzing campaign for the decoders | planned | `n/a (planned)` | `security/run/fuzz.sh` |
| C-003 Threat and control coverage governance | implemented | `make security-preflight` | `tests/test_security_governance.py` |
| C-004 Pinned Python dependencies and Rust toolchain | implemented | `make check` | `requirements.txt` |
| C-005 Software composition analysis (pip-audit) | implemented | `make security-sca` | `security/run/sca.sh` |
| C-006 Automated dependency updates | implemented | `n/a` | `.github/dependabot.yml` |
| C-007 Hash-pinned Python dependencies | planned | `make security-sca` | `security/run/sca.sh` |
| C-008 GitHub Actions pinned by commit SHA | implemented | `make security-preflight` | `.github/workflows/ci.yml` |
| C-009 CI workflow security analysis | implemented | `make security-actions` | `security/run/actions.sh` |
| C-010 Secret scanning | implemented | `make security-secrets` | `security/run/secrets.sh` |
| C-011 Pre-commit security hooks | implemented | `pre-commit run --all-files` | `.pre-commit-config.yaml` |
| C-012 Deployment artifact digest manifest | implemented | `make deploy-check` | `deploy/manifest.json` |
| C-013 Input size and resource limits | implemented | `make security-api-check` | `services/ingest/app.py` |
| C-014 Signed release provenance | planned | `make security-sbom` | `security/run/sbom.sh` |
| C-015 Property-based tests for the security-critical library | implemented | `make test` | `tests/test_properties.py` |
| C-016 Truncation and mutation robustness tests | implemented | `make rust` | `tools/s7comm-dpi/tests/robustness.rs` |
| C-017 API key authentication with constant-time comparison | implemented | `make security-api-check` | `services/ingest/auth.py` |
| C-018 Rate limiting and request body caps | implemented | `make security-api-check` | `services/ingest/app.py` |
| C-019 Prompt-injection isolation and adversarial tests | implemented | `make security-ai-check` | `tests/test_ingest_ai_security.py` |
| C-020 Model output schema validation, never executed | implemented | `make security-ai-check` | `services/ingest/ai.py` |
| C-021 No tool access and mandatory human review | implemented | `make security-ai-check` | `services/ingest/ai.py` |
| C-022 LLM adversarial test suite (OWASP LLM Top 10) | implemented | `make security-ai-check` | `tests/test_ingest_ai_security.py` |
| C-023 Detection evasion testing | planned | `n/a (planned)` | `tools/evasion_check.py` |
| C-024 Structured audit log for API and triage decisions | implemented | `make security-api-check` | `services/ingest/app.py` |
| C-025 Non-root, read-only service container | planned | `n/a (planned)` | `services/ingest/Dockerfile` |
| C-026 Container image scanning | planned | `n/a (planned)` | `security/run/container.sh` |
| C-027 Security requirements mapped to NIST SSDF and OWASP ASVS | implemented | `n/a` | `docs/SECURITY_REQUIREMENTS.md` |
| C-028 Secure code review checklist | implemented | `n/a` | `docs/SECURE_CODE_REVIEW.md` |
| C-029 Vulnerability disclosure and remediation SLA | implemented | `n/a` | `SECURITY.md` |
