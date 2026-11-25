# Three-minute demo

A reviewer can see the whole loop offline, without Docker or the lab. Run these
commands in order.

## 0:00 — The decoder-to-query path

```bash
make setup
make demo
```

What to say: a DNP3, Modbus, S7comm and OPC UA frame is decoded by the Rust decoders,
matched against the Sigma rules, and converted into Loki, Splunk, Sentinel and
OpenSearch queries. This is the smallest end-to-end slice: bytes → event → rule
→ query.

## 0:30 — The alert flood

```bash
make case-study
```

What to say: a real lab run produced **151 alerts across 17 types from four
sources in 160 seconds**. The analysis collapses them into **24 one-minute
episodes** and **five operational events** — four adversary campaigns and one
sensor-health event. The duplicate ratio is **84.1%**, and every alert is still
counted.

Point at:

- `analysis/out/report.md` — generated tables and timeline.
- `docs/CASE_STUDY_ALERT_FLOOD.md` — what to suppress and what not to.

## 1:15 — Purple-team replay

```bash
make purple-check
```

What to say: the 2026-11-24 plan covers **8 steps and 14 expectations**:
enterprise pivot, process safety, DNP3, OPC UA, S7comm, and a PowerShell operator
write. **14/14 lab alert signals replayed, 0 unexpected alerts, benign window
passed.** The replay matches the lab's alert labels, not the repository's rules.
The MTTD run is separate: **4/4, mean 2.45 s (`n=4`, one run)**, because the
replay snapshot has alert timestamps but not action start timestamps.

Point at `docs/PURPLE_TEAM.md` and `deploy/evidence/purple/`.

## 1:30 — Do the converted queries run?

```bash
make parity-up        # Splunk Free and OpenSearch containers
make engine-parity
```

What to say: every single-event rule is converted to Splunk SPL, OpenSearch PPL
and Sentinel KQL. **30/30 rules return exactly the same event set as the
repository matcher in each engine.** The run caught a real conversion bug: PPL
escaped the underscore in `event_type="login\_failure"`, so the query was valid
and matched nothing. Point at `docs/ENGINE_PARITY.md`.

## 1:40 — Safety when the level sensor lies

```bash
make process-model-check
```

What to say: the independent mass balance estimates the tank level from the
flows and never reads the reported level. In the spoof scenario the reported
value is pinned near 40% and a shadow monitor stays quiet; the estimate reaches
**94%** and the safety rule fires. **Normal cycle quiet, unsafe command
detected.** Point at `docs/PROCESS_SAFETY.md`.

## 1:50 — Operational ownership

```bash
make health-check
sed -n '1,40p' deploy/evidence/health/report.md
```

What to say: **73 rules, 6 stable, 12 with observed lab volume.** The other 67
are experimental and carry at least one operating gap; the health gate has 0
blocking gaps. Every
stable rule has a runbook and a validation date; the 67 experimental rules are
explicitly flagged, not hidden. The catalogue joins to the lab analysis so an
expected volume cannot silently drift.

Point at `metadata/detection-catalog.yaml` and `docs/runbooks/`.

## 2:20 — Performance

```bash
make perf-check
sed -n '1,35p' docs/PERFORMANCE.md
```

What to say: on the recorded host, the decoders process **7.8–11.0M frames/s**
with **p99 60–190 ns per frame**; the offline matcher replays **~2,800 events/s**
over 1,000 distinct benign events ten times.
through 24 rules at p99 ~963 µs, with **0 matches on benign events**. The numbers
are hardware- and frame-size-specific; there is no pcap replay or backpressure
test.

## 2:50 — Close

```bash
make check
```

What to say: the loop is the product: threat model → telemetry → detection →
fixture and held-out tests → conversion → purple team → catalogue and runbooks →
performance. The repo is explicit about the limits: generated benign data, a
Dockerised lab, 67 experimental rules, and no production SOC.

## If you have ten minutes

Read, in order:

1. `docs/CASE_STUDY_ALERT_FLOOD.md` — judgment on real lab data.
2. `docs/PURPLE_TEAM.md` — detection coverage and what is lab-only.
3. `docs/OPERATIONS.md` — one rule from catalogue to rollback.
4. `docs/DESIGN_DECISIONS.md` — tradeoffs and the rule that was withdrawn.
5. `docs/CLAIMS.md` — every number and the command that proves it.
