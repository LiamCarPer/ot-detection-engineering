# Scope and limitations

The README states the headline. This page states the detail behind it, because a
detection is only as trustworthy as the evidence and the limits around it.

## What is machine-checked

Every Sigma rule is parsed, tagged, converted and tested in CI; every native,
YARA, baseline, conduit and stateful rule has a committed proof. Native rules are
executed by Suricata over committed captures; the Loki ruler bundle is executed
in a full stack; the decoders' output is run through the same matcher the rule
tests use. Coverage, fixture metrics, all-family false positives and held-out
metrics are derived from the rules. The lab alert-flood analysis is regenerated
from a pinned snapshot and checked for drift. All of that runs offline and
deterministically.

## What is emulated

The lab is a Dockerised software emulation of a segmented water-treatment plant.
There is no physical PLC, sensor or actuator. The emulation figures come from a
recorded run against that lab.

## Fixture and held-out metrics

- **Fixture metrics are agreement, not field performance.** Precision and recall
  are computed against fixtures authored alongside each rule. They measure that
  the rule and its fixtures agree; they are a regression guard, not a production
  precision claim.
- **Held-out metrics are a better estimate, still not field performance.** The
  labels in `metrics/heldout/` are authored independently of the rule fixtures,
  and the negatives come from a different generator seed plus one near miss per
  rule. The set is small (two positives per rule), so per-rule intervals are
  wide; quote the aggregate.
- **The benign baseline is generated, not harvested.** It is 1,000 deterministic
  events from `tools/make_benign.py` (seed `20260101`). The Sigma single-event
  claim is `0/1,000` with a 95% Wilson upper bound of **0.38%**, not "0.0 FPR".
  The corpus cycles 37 behavioural shapes, so the binomial interval over 1,000
  rows overstates the effective sample size. Behaviour-baseline, conduit,
  correlation and stateful rules are measured separately in
  [`deploy/evidence/fpr/report.md`](../deploy/evidence/fpr/report.md); that report, not the Sigma
  interval, is the all-family claim.
- **The stateful baselines are not field baselines.** The process envelope is
  built from the generated benign corpus; the per-asset protocol profile is
  learned from the held-out generated seed (`20260202`). They are reviewable,
  not production-trained.

## Emulation scope

The **MTTD run** covers two adversary steps and four expectations and has action
start timestamps. The **2026-11-24 replay** covers eight steps and fourteen
expected lab alert signals; it matches lab `alert_type` labels, not this
repository's rules, and has alert timestamps only, so it does not report MTTD.
Neither run exercises every rule.

## Other committed models

- **The behaviour baseline is a snapshot.** The deviation rules are only as
  current as `baseline/ot-behaviour.json`, learned from the held-out benign seed
  (`metrics/heldout/negatives.jsonl`). A legitimate network change requires
  regenerating it; a stale baseline is a reviewable event, not a silent source of
  false positives.
- **YARA fixtures are synthetic.** The samples contain the structural markers the
  rules target (an `MZ`/`PE` signature next to a project or firmware marker) and
  are inert. Real malware is never committed; the engine is proven with the EICAR
  test string assembled in memory.
- **The conduit policy is a committed model of intent.** The conduit rules are
  only as good as `metadata/ot-conduit-policy.yaml`. Traffic with an unzoned
  endpoint is out of scope by design. The lab firewall is the enforcement point
  and the two are reconciled by review; a difference is a finding, not a second
  source of truth.
- **The change calendar is policy, not an integration.** The stateful
  change-window rule joins `metadata/change-calendar.yaml`. It is not connected to
  a live change-management system.

## Protocol and platform limits

- The S7comm decoder handles classic S7comm only, not S7comm Plus.
- OPC UA service bodies are visible only on unencrypted channels (`None`/`Sign`,
  not `SignAndEncrypt`).
- The DNP3 decoder reads the first object header only.
- The native Modbus/DNP3 rules require Suricata's application layer to be
  enabled.
- Splunk and OpenSearch queries were executed against the held-out corpus in
  the engine-parity run (30/30 in each engine), but not against a production
  schema, volume or deployment. The generated Splunk bodies still need an
  index/sourcetype stanza; see `deploy/DEPLOY.md`.

## Correlation and Loki

The pinned Loki backend's ruler output wrapped a correlation in
`count_over_time()`, which a metric expression cannot accept, and interpolated a
rule document into a stream selector. Loki rejected the generated rule. The
bundle now builds correlation ruler documents from the backend's default-format
query; see `pipelines/loki_correlation.py`. A test guards the shape, because the
failure mode is a rule silently absent at runtime.

## CI versus local validation

CI runs the offline checks and the decoder, collector, behaviour-baseline,
conduit, stateful, YARA, all-family false-positive, detection-health,
case-study and purple-replay proofs in read-only mode. The container validations
(Suricata, Loki, Malcolm) and the live-lab capture require Docker or the lab, so
they run locally and their committed evidence is guarded by tests rather than
re-run on every commit.
