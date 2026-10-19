# Security requirements

This maps the repository's controls to two externally recognised frameworks:
**NIST SSDF (SP 800-218)** for the secure development lifecycle, and **OWASP
ASVS 5.0** for application security verification. Status is honest: `met`,
`partial`, or `planned`. The control ids refer to
[`metadata/security-controls.yaml`](../metadata/security-controls.yaml), and the
generated coverage is in `coverage/out/security_coverage.md`.

## NIST SSDF (SP 800-218)

| Practice | Requirement | Controls | Status |
| :--- | :--- | :--- | :--- |
| PO.1 | Define security requirements for the software | C-003, C-027 | met |
| PO.3 | Implement supporting toolchains (pinned, reproducible) | C-004, C-007 | partial — toolchain pinned, Python hashes planned |
| PO.5 | Secure development environments | C-008, C-011 | met — actions SHA-pinned, pre-commit hooks |
| PS.1 | Protect code from unauthorized access | C-008, C-011 | met |
| PS.2 | Verify release integrity | C-012, C-014 | partial — digest manifest exists, signing planned |
| PS.3 | Archive and provenance | C-012, C-014 | partial — provenance manifest, SBOM planned |
| PW.4 | Reuse well-secured software | C-005, C-006 | partial — updates automated, continuous SCA planned |
| PW.5 | Follow secure coding practices | C-001, C-013, C-028 | met |
| PW.6 | Configure build for security | C-001, C-016 | met — `forbid(unsafe_code)`, overflow checks, robustness tests |
| PW.7 | Review and analyze code for vulnerabilities | C-009, C-028 | partial — review checklist met, SAST planned |
| PW.8 | Test executable code | C-001, C-015, C-016 | met — robustness + property-based tests |
| PW.9 | Secure defaults | C-013, C-025 | partial — decoder limits, service hardening planned |
| RV.1 | Identify vulnerabilities continuously | C-005, C-010, C-023 | partial — evasion testing planned, SCA/secrets planned |
| RV.2 | Assess, prioritize and remediate | C-029 | met — severity and SLA table |
| RV.3 | Root-cause analysis | C-029 | partial — process defined, no advisory yet |

## OWASP ASVS 5.0

| Category | Requirement | Controls | Status |
| :--- | :--- | :--- | :--- |
| V1 Encoding and sanitization | Untrusted input is validated and never interpreted | C-001, C-013 | partial — parsers met, ingest API planned |
| V2 Validation and business logic | Input has shape, size and rate limits | C-013, C-018 | planned |
| V4 API and web service | Authenticated, rate-limited, schema-validated API | C-017, C-018 | planned |
| V6 Authentication | Constant-time secret comparison, no default credentials | C-017 | planned |
| V8 Authorization | Only authenticated clients submit telemetry | C-017 | planned |
| V13 Configuration | Secure defaults, no debug in production, non-root container | C-025 | planned |
| V14 Data protection | No secrets or raw credentials in logs; telemetry minimised in prompts | C-019, C-024 | planned |
| V15 Secure coding and architecture | Threat model, layered controls, fail-safe behaviour | C-003, C-027 | met |
| V16 Logging and error handling | Decisions auditable; errors do not leak internals | C-024 | planned |

## Honest scope notes

- The repository has **no web application** until the ingest service lands, so
  the API and authentication rows are `planned`, not claimed.
- `met` means the control exists and its evidence path is checked by
  `tests/test_security_governance.py`; it does not mean an external audit.
- Coverage is generated from the threat model, so a threat with only planned
  controls is visible in the report rather than assumed to be handled.
