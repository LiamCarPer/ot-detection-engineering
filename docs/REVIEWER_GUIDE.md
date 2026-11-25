# Reviewer guide

This repository is a detection-engineering portfolio, not a product. The goal of
this page is to let a reviewer choose a depth and get to the evidence quickly.

## Choose a path

| Time | Path | What you will see |
| :-- | :-- | :-- |
| 3 min | [`docs/DEMO.md`](DEMO.md) | The offline demo path: decoders, case study, purple team, catalogue, performance. |
| 2 min | [`docs/RESULTS.md`](RESULTS.md) | The numbers, their scope, and what they do not mean. |
| 5 min | [`docs/CASE_STUDY_ALERT_FLOOD.md`](CASE_STUDY_ALERT_FLOOD.md) | Real lab data: 151 alerts → 24 episodes → 5 operational events, with the triage judgment. |
| 8 min | [`docs/STATE_DETECTIONS.md`](STATE_DETECTIONS.md) | Drift, change-window and per-asset behaviour: what needs context, and why. |
| 8 min | [`docs/PERFORMANCE.md`](PERFORMANCE.md) | Decoder p99, replay throughput, SLOs and what they do not measure. |
| 8 min | [`deploy/evidence/health/report.md`](../deploy/evidence/health/report.md) | Owners, runbooks, observed volume and the stable/experimental split. |
| 10 min | [`deploy/report.md`](../deploy/report.md) | Functional validation: Suricata, Loki, Malcolm, decoders, collector. |
| 15 min | [`docs/CLAIMS.md`](CLAIMS.md) | Every headline claim mapped to an artifact and a command. |
| 30 min | [`docs/ARCHITECTURE.md`](ARCHITECTURE.md), [`docs/DESIGN_DECISIONS.md`](DESIGN_DECISIONS.md) | The data flow, the tradeoffs, and the rules that were withdrawn. |
| Deep dive | This page's "Where to be skeptical" and the code paths below. | The parts a staff engineer will actually probe. |

## The 10-minute code path

If you only read code, read these in order:

1. [`tools/otde/matcher.py`](../tools/otde/matcher.py) — the validation matcher.
   It builds on pySigma's parsed model and raises on unsupported features rather
   than silently passing a test. That is the difference between a fixture suite
   and a fixture suite that can lie.
2. [`tools/otde/correlation.py`](../tools/otde/correlation.py) — the windowed
   evaluator for `value_count` and `event_count`.
3. [`tools/dnp3-dpi/src/lib.rs`](../tools/dnp3-dpi/src/lib.rs) and
   [`tools/modbus-dpi/src/lib.rs`](../tools/modbus-dpi/src/lib.rs) —
   dependency-free decoders with CRC-16/DNP validation, bounds checks and
   robustness tests.
4. [`pipelines/convert.py`](../pipelines/convert.py) — one Sigma source to four
   backends, with SHA-256 provenance and an explicit unsupported list.
5. [`purple/runner/run_emulation.py`](../purple/runner/run_emulation.py) — the
   emulation runner, including the check that the lab's `mitre_id` matches the
   plan's declared `lab_technique`.
6. [`metrics/heldout_eval.py`](../metrics/heldout_eval.py) — per-rule precision,
   recall and false-positive rate with Wilson intervals.
7. [`analysis/lab_case_study.py`](../analysis/lab_case_study.py) — alert
   normalization, episode collapse and campaign clustering on real lab data.
8. [`tools/detection_health.py`](../tools/detection_health.py) — the catalogue
   gate: one entry per rule, stable rules need runbooks and observed volume.
9. [`tools/otde/stateful.py`](../tools/otde/stateful.py) — drift, change-window
   and per-asset protocol evaluation.
10. [`tools/perf/src/main.rs`](../tools/perf/src/main.rs) — the decoder
    microbenchmark, and [`tools/perf_check.py`](../tools/perf_check.py) for
    the replay and evidence.

## What this repository answers

| Question | Where |
| :-- | :-- |
| How do you keep rules, fixtures, coverage and metrics from drifting? | [`docs/ARCHITECTURE.md`](ARCHITECTURE.md), `tests/test_metadata.py`, `tests/test_coverage.py` |
| How do you validate a rule against something other than its own fixture? | [`metrics/heldout/README.md`](../metrics/heldout/README.md), [`docs/CLAIMS.md`](CLAIMS.md) |
| How do you prove the native rules actually fire? | [`deploy/report.md`](../deploy/report.md), `make suricata-check` |
| How do you prove the Sigma rules work in a real SIEM? | [`deploy/report.md`](../deploy/report.md), `make loki-check` |
| How do you handle a rule that turns out to be wrong? | [`docs/DESIGN_DECISIONS.md`](DESIGN_DECISIONS.md) — the T0832 withdrawal |
| How do you turn an alert flood into operational events? | [`docs/CASE_STUDY_ALERT_FLOOD.md`](CASE_STUDY_ALERT_FLOOD.md), `make case-study` |
| How do you own a rule after it ships? | [`deploy/evidence/health/report.md`](../deploy/evidence/health/report.md), [`docs/runbooks/`](runbooks/), `make health` |
| How do you detect something that needs context? | [`docs/STATE_DETECTIONS.md`](STATE_DETECTIONS.md), `make stateful-check` |
| Does it work at scale? | [`docs/PERFORMANCE.md`](PERFORMANCE.md), `make perf-check` |
| How do you validate detections against an adversary? | [`docs/PURPLE_TEAM.md`](PURPLE_TEAM.md), `make purple-check` |
| How would you operate one of these rules? | [`docs/OPERATIONS.md`](OPERATIONS.md), [`docs/runbooks/`](runbooks/) |
| How do you measure a detection programme? | [`docs/RESULTS.md`](RESULTS.md), `make metrics` |
| How do you emulate an adversary and score it? | [`purple/emulation/lab-run.md`](../purple/emulation/lab-run.md), `make emulate-validate` |

## Where to be skeptical

This section exists because a reviewer should not have to discover the weak
points alone. These are the questions I would ask.

- **The benign corpus is generated.** The Sigma single-event claim is `0/1,000`
  with a 95% Wilson upper bound of 0.38%; it is a bound on modelled normal
  operation, not a field FPR, and the corpus has only 30 behavioural shapes. The
  all-family result (baseline, conduit, correlation, stateful, native, YARA) is
  in `deploy/evidence/fpr/report.md`. The generator is in `tools/make_benign.py`; the
  provenance and limits are in `metrics/baseline/README.md`.
- **The held-out labels are authored, not captured.** They are separate from the
  rule fixtures and use a different seed, but they are not independent field
  data. Per-rule intervals are wide because there are two positives per rule.
- **The purple-team evidence is small.** The 2026-11-24 replay is 8 steps / 14
  expected lab signals and matches lab alert labels, not this repository's rules;
  the MTTD run is 2 steps / 4 expectations and is `n=4`, not a benchmark. The
  runner checks the lab's `mitre_id` against the plan, because several lab labels
  differ from the repository's rule mapping; the difference is declared, not
  hidden.
- **The live-lab proof is a subset and a snapshot.** Eleven of the thirteen
  rules the lab exercises fire in the committed 2026-09-15 run (lab revision
  `11a17f7`). That snapshot predates the P1 rule changes; a fresh lab run is
  required to re-confirm the changed rules. The newer breadth rules are
  fixture-proven and included in the bundle, but they are not all
  live-executed.
- **Coverage is prioritized, not maximized.** `32 / 97` is raw ATT&CK for ICS
  coverage. Privilege Escalation is deliberately `0/2` because the repo has no
  host/auth telemetry. Padding that number with network rules would be
  tag-gaming.
- **The lab is a Dockerised plant.** There is no physical PLC, sensor or
  actuator. The safety monitor sees a simulated process, not a real one.
- **The case study is one lab burst.** 151 alerts in 160 seconds is not a
  production queue, and there are no analyst action timestamps, so it does not
  compute time saved. It computes queue reduction.
- **The performance numbers are not production numbers.** The host is a desktop,
  the decoder frames are small, there is no pcap replay or backpressure test,
  and the replay benchmark measures the Python validation matcher.
- **The stateful baselines are not field baselines.** The process envelope is
  built from the generated benign corpus and the per-asset profile from a
  disjoint generated seed. They are reviewable, not production-trained.
- **Purple-team replay and MTTD come from different runs.** The 2026-11-24 run
  replays 14/14 lab alert signals across 8 steps with 0 unexpected alerts; it
  matches lab labels, not this repository's rules. The 2026-09-13 run is the only
  one with action start timestamps and provides the 2.45 s MTTD.
- **HMI-login, C2-beacon and OT-port-scan are lab-only.** They are not scored
  because the repository has no matching rule.
- **Only six rules are `stable`.** The other 67 are `experimental` and most
  have no runbook or observed volume. That is the honest state of the
  catalogue, not a claim that every rule is operationally ready.
- **The security/AI workstream is supporting evidence.** The threat model,
  controls, ingest API and LLM triage are real and tested, but they are not the
  OT detection story.

## How to run it offline

```bash
make setup
make demo       # decoder -> Sigma match -> generated SIEM queries, no Docker
make check      # lint, Sigma validation, tests, Rust, bundle drift
make metrics    # coverage, fixture/held-out metrics, emulation replay
make case-study # regenerate the lab alert-flood analysis
```

The container and live-lab checks are separate:

```bash
make suricata-check   # Docker
make loki-check       # Docker
make lab-loki-check   # requires OT-Security-Lab running
```

## What this is not

- Not production telemetry.
- Not a 24/7 SOC or an on-call rota.
- Not a commercial BAS deployment.
- Not a malware sample repository; the YARA fixtures are inert and the engine is
  proven with the EICAR test string assembled in memory.
