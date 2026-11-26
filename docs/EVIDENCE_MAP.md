# Evidence map

Every independent run behind the headline claims, with its date, what it
exercised, and what it does not prove. If a claim is not in this table and in
[`CLAIMS.md`](CLAIMS.md), it is not supported.

| Run | Date | Exercised | Result | Does not prove |
| :-- | :-- | :-- | :-- | :-- |
| Coverage efficacy | Every commit | 32 tagged techniques | 32 validated (fixture + independent measurement + clean benign); 10 live-lab proven (`coverage/out/`) | The 97-technique denominator still includes host/auth/process techniques this telemetry cannot see |
| Rule fixtures | Every commit | 30 single-event Sigma rules, 7 correlation rules, 4 YARA rules, 3 baseline, 3 conduit, 5 stateful | `make test` green; precision/recall 1.0 against the rule's own fixtures | Field precision or recall |
| Held-out single-event | Every commit | 54 positives against 1,024 generated negatives per rule plus one near miss | 54 / 54, 0 false positives (`95% CI 0.9336–1.0`) | Independence from the generator; two positives per rule leaves a wide interval |
| Held-out correlation | Every commit | 13 positive and 15 negative windows across seven rules | 13 / 13, 0 false positives | Timing realism; windows are authored |
| Held-out YARA | Every commit | 8 labelled artifacts against 8 shared negatives | 8 / 8, 0 false positives | Real malware; fixtures are synthetic |
| All-family false positives | Every commit | 73 rules against 1,000 generated benign events plus benign captures and fixtures | Sigma, baseline, conduit, correlation, stateful, native and YARA all 0 (`deploy/evidence/fpr/report.md`) | Field traffic; the corpus has 30 behavioural shapes |
| Decoder-to-rule | Every commit | 35 events across DNP3, Modbus, S7comm and OPC UA | The decoded events fire the expected Sigma rules (`deploy/evidence/decoders/`) | TCP reassembly, IP endpoints, encrypted OPC UA |
| Collector-to-rule | Every commit | 62 events from 20 Suricata, Zeek, NetFlow, SNMP, Sysmon, nginx-auth, PLC-diagnostic and health samples | The normalized events fire the expected rules (`deploy/evidence/collector/`) | Live sensor coverage; NetFlow/SNMP samples are authored |
| Behaviour/conduit/stateful proofs | Every commit | 3 baseline rules, 3 conduit rules, 5 stateful rules | All pass on their committed windows (`deploy/evidence/{baseline,conduit,stateful}/`) | Field baselines, real change tickets, production source scopes |
| Native Suricata | 2026-11-25 | 8 PCAPs, 21 native SIDs | 21 / 21 SIDs fire, benign captures silent (`deploy/evidence/summary.json`) | Real plant traffic; captures are generated |
| Malcolm pipeline | 2026-11-25 | 8 PCAPs, 59,185 rules loaded | The ruleset loads beside Malcolm's defaults and fires (`deploy/evidence/malcolm/`) | A production sensor or a sustained load |
| Loki live stack | 2026-11-25 | 18 generated ruler rules | 18 / 18 fire in a full Loki stack, benign phase clean (`deploy/evidence/loki/`) | The other 50 rules; Loki is not the only backend |
| Lab live rules | 2026-09-15 | 11 generated rules against OT-Security-Lab revision `11a17f7` | 11 rules firing; 24 normalized events (`deploy/evidence/lab-loki/`) | **Predates the P1 rule changes.** A fresh lab run is required to re-confirm live execution of the changed rules. |
| Purple-team live | 2026-11-25 | 7 steps, 12 Sigma expectations, 3 runs | 11 / 12; 0 unexpected; benign windows clean; mean MTTD 2.43 s (`deploy/evidence/purple-live/`) | Rule coverage of the lab model, not a plant; the process-safety miss was an untimed write; the re-run was blocked by the intake PLC runtime |
| Purple-team replay | 2026-11-24 | 14 expected lab alert signals across 8 steps | 14 / 14, 0 unexpected, benign window passed (`deploy/evidence/purple/`) | Rule execution or MTTD: it replays the lab's `alert_type` snapshot |
| MTTD run | 2026-09-13 | 4 expectations across 2 steps | 4 / 4, mean 2.45 s (`n=4`, one run) | Breadth or repeatability; one run |
| Suppression | 2026-11-25 | 151-alert snapshot through the grouping policy | 21 notifications, 86.09% reduction; C2/C3/C4/C5 preserved (`analysis/out/suppression.json`) | Not a live Alertmanager replay; register is not a group key |
| Incident | 2026-11-25 | Three unauthorized Modbus writes, armed responder | Detected, gateway block verified, block removed, responder returned to dry-run (`docs/INCIDENT_2026-11-25.md`) | Lab containment, not a plant change-management or host eradication action |
| Sensor health | 2026-11-25 | Watchdog event for a stopped DNP3 producer | The repository rule fired in the lab ruler (`deploy/evidence/lab-health/`) | One producer, one event; not a full sensor-health baseline |
| Alert-flood case study | 2026-11-24 | 151 lab alerts, 17 types, 4 sources | 24 one-minute episodes, 5 operational events (`analysis/out/`) | Analyst MTTA or production queue behaviour |
| Lab proof | On demand | Live health, live rules, live purple, engine parity, benign capture | One summary with per-step status; attacks skipped while a capture runs (`deploy/evidence/lab-proof/`) | Live steps need the lab; no self-hosted runner, so the run is local |
| Process safety | 2026-11-25 | 3 simulated scenarios through the committed rule | Normal quiet; unsafe detected; spoofed sensor detected from the estimate, shadow blinded (`deploy/evidence/process-model/`) | Two-flow model, not plant data; live timing still separate |
| Allowlists | Every commit | 6 sets from 15 inventory assets | Every Sigma filter and native exclusion bound; generated file current (`metadata/allowlists.generated.yaml`) | Lab policy; DNP3 link addresses are not IPs; S7 Sigma has no standing allowlist by design |
| Lab benign capture | 2026-11-26 | 25.45 h gateway PCAP; Zeek `-C`, Modbus DPI, Suricata | Sigma 0, native 0; lab-trained baseline 0 / 1,041,580; 9/30 Sigma rules exercised (`deploy/evidence/benign-lab/`) | Only Modbus/flow; 21 rules unexercised; committed baseline domain shift; ~56% observability flows |
| Engine parity | 2026-11-25 | 30 single-event rules in Splunk Free, OpenSearch PPL and Kusto | 30 / 30 exact event-set match in each engine (`deploy/evidence/engine-parity/`) | One lab corpus; single-event rules only; engines pinned by image tag, not digest |
| Sustained load | 2026-11-25 | 4,000 and 20,000 EPS through 30 rules with a 10,000 queue | 4,000 target: ~3,375 achieved, 0 drops; 20,000: ~70.8% drops and a full queue (`deploy/evidence/load/`) | Single-process Python matcher, not a pcap sensor or production backpressure |
| Performance | 2026-11-25 | DNP3, S7comm and OPC UA decoder microbenchmark; 1,000 benign events × 10 through 30 rules | 7.8–11.0M frames/s; ~2,800 replay events/s; per-frame p99 60–190 ns (`deploy/evidence/perf/`) | Production throughput, pcap replay, backpressure, SIEM cost |

## Evidence hierarchy

1. **Field evidence** — none. There is no production telemetry.
2. **Lab evidence** — the live-lab and purple-team runs, and the case study.
   They are real runs against a Dockerised plant, not a field deployment.
3. **Held-out evidence** — authored positives and generated negatives. Better
   than fixtures, still not field data.
4. **Fixture evidence** — regression checks written with the rule.

The repository's claims should be read at the level of the evidence that
supports them, not one level higher.

## Reproduce

```bash
make check        # fixtures, held-out, all-family FPR, decoder, collector,
                  # baseline, conduit, stateful, performance, deploy, health
make metrics      # coverage, held-out, purple replay
make fpr          # all-family false-positive report
make suricata-check  # Docker; native rules over the captures
make loki-check      # Docker; the ruler stack
make lab-loki-check  # requires OT-Security-Lab running
make case-study      # the alert-flood analysis
```
