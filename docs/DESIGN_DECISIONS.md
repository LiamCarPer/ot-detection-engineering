# Design decisions and tradeoffs

This document records why the repository is built the way it is, including the
things that went wrong. It is the companion to [ARCHITECTURE.md](ARCHITECTURE.md):
that file describes the system, this one explains the reasoning and the limits.

## Why two detection formats instead of only Sigma

Sigma models log events, not industrial protocol semantics. There is no Sigma
vocabulary for "Modbus function code 6", "a DNP3 object header", or "an S7comm
program download at a fixed offset in a COTP data PDU". Forcing those into Sigma
would mean encoding protocol structure into field names and losing fidelity.

So detection content is split by what each format can actually express:

- **Sigma** for log-based detections — zone firewall decisions, NDR alerts,
  application and process events. Portable and testable offline.
- **Native Suricata** for protocol DPI, where the engine already parses Modbus,
  DNP3, OPC UA and S7comm framing.

Both formats carry an ATT&CK for ICS technique and feed the same coverage map,
so the split does not fragment governance.

## Why Rust decoders instead of only Suricata rules

Suricata can see a DNP3 function code, but not the application semantics the
Sigma rules want — the object group, the control code, the link source address
that identifies a master. Where no application-layer parser exists, a small
decoder is the honest way to get those fields.

The decoders are dependency-free (`#![forbid(unsafe_code)]`) and validate
framing — CRC-16/DNP for DNP3 — so the events the rules run on are trustworthy.
They emit a normalized contract (`docs/TELEMETRY.md`) rather than
vendor-specific JSON, so the detection content is not tied to the decoder.

## Why a pySigma-based matcher that fails loudly

The rule tests need to evaluate a parsed Sigma rule against an event without a
SIEM. Re-implementing Sigma would drift from the reference implementation, so the
matcher builds on pySigma's own parsed model and only interprets the resulting
tree. When it meets a feature it does not implement — a field reference, say — it
raises `UnsupportedFeatureError` instead of returning a pass. A test that never
really exercised the rule is worse than no test.

## Why the SID range 9000000-9000099

Native rules need unique signature ids. The first attempt used
`1000001-1000028`, which collided with the NSacyber ELITEWOLF rules that Malcolm
ships (`1000000-1001022`); Suricata rejected the whole ruleset as duplicates. The
repository now reserves `9000000-9000099`, a private block above the Emerging
Threats and ELITEWOLF ranges, and a test enforces both the range and uniqueness.

## Why one source of truth and recorded provenance

A rule is authored once. The Loki, OpenSearch, Splunk and Sentinel queries are
generated from it, never hand-maintained, and the deployment bundle records the
SHA-256 of the rule revision that produced each artifact. `--check` fails CI when
the committed bundle drifts, so a rule change cannot silently leave a stale
query in the bundle.

## Why offline-first

CI has no SIEM, no lab and no external data source. The ATT&CK for ICS catalog
is pinned in-tree, fixtures are committed, dependencies are pinned, and the
container, Malcolm and live-lab validations run locally with their evidence
committed and guarded by tests. This keeps the check fast and reproducible and
means a contributor can work without infrastructure.

## Things that went wrong, and what they taught

These came out of actually running the detections rather than assuming they
worked, and they are the reason the repository validates functionally:

- **Modbus and DNP3 application-layer detection is disabled by default in
  Suricata.** The stock configuration ships `app-layer.protocols.modbus.enabled:
  no` and the DNP3 equivalent, so the ruleset will not load until both are
  enabled. Any deployment must set them.
- **The original Modbus exception-burst rule was invalid.** `modbus: function >
  128` is not valid syntax, and the legacy `modbus` keyword matches requests only,
  so exception responses cannot be inspected that way. It was replaced with a
  request-side detection of writes past any plausible register map.
- **`service_name` is a reserved label in Loki.** Loki promotes a `service_name`
  field to a stream label, so `| logfmt` renames the extracted field and a rule
  filtering on `service_name` never matches. The OPC UA decoder emits
  `opcua_service` instead.
- **The generated LogQL had no logsource selector.** The queries matched
  `{job=~".+"}` and filtered on fields, so a deployment that pours every protocol
  into one stream could cross-fire rules across protocols — a Modbus rule firing
  on DNP3 function codes. pySigma's Loki backend does not encode the logsource
  into the stream selector, so `pipelines/loki_pipeline.py` now sets the
  backend's `logsource_loki_selection` attribute from the rule's logsource
  service; the generated queries select `{job=~".+", service="modbus"}`, and a
  test guards the mapping.
- **The lab's Modbus path is not normalized NDR telemetry.** The lab reports
  Modbus as JSON alert events, so the generated Modbus queries have no input
  there and are validated by the offline decoder proof instead. Two generated
  rules are therefore not part of the live-lab evidence.
- **Suricata appends to `eve.json`.** Re-running validation merged new alerts
  with committed evidence until the runner started from a clean directory.
- **Adding a correlation rule would have silently deleted an existing alert.**
  pySigma suppresses the output of every rule a correlation references unless the
  correlation sets `generate: true`. The Modbus process-read rule is a
  smoke-tested detection in its own right, so the correlation sets it
  deliberately, and a test asserts that an artifact either exists or is recorded
  as unsupported — never quietly absent.
- **Correlation conversion is not backend-neutral.** Of the four pinned targets,
  Loki, Splunk and OpenSearch implement `correlation_methods`; the Kusto backend
  does not, so the correlation is recorded as unsupported for Sentinel in the
  manifest rather than being silently dropped from the bundle.
- **pySigma's Loki correlation conversion mutates the rule in place.** It appends
  the counted field to the rule's `group-by` list, so converting several targets
  from one loaded ruleset corrupted the Splunk and OpenSearch queries: the
  distinct count had the field it was counting added to its own grouping and
  could never reach the threshold. Each target now loads its own copy, and the
  generated queries are committed where the difference would be visible.
- **A referenced rule keeps its own artifact only with
  `finalize_correlation_subqueries`.** Without it the rule is emitted
  unfinalised, so its Splunk saved search loses its stanza the moment a
  correlation starts referencing it.
- **A correlation cannot be parsed standalone.** pySigma resolves references at
  parse time, so tooling that reads one file at a time has to pass
  `resolve_references=False`, and any conversion has to load the whole ruleset.
- **Conversion order is a dependency, and the local run passed by luck.** A
  correlation reads the conversion result of the rules it references, and
  pySigma's backreference sort is not a total order, so the effective order still
  depends on the order the directory was listed in. That was green on the
  developer's machine and red in CI, which is the useful version of that failure.
  `conversion_order()` now resolves the dependency explicitly and refuses to guess
  when it cannot — a missing reference or a cycle is an error, not a coin flip.

## Known limitations

- **Coverage is intentionally low** (16 of 97 ICS techniques). The point is the
  engineering process, which scales unchanged to a large ruleset.
- **Fixture precision and recall measure rule/fixture agreement**, not field
  performance, and the benign baseline is 50 authored events covering normal
  traffic for every protocol and stream the rules consume.
- **Detection is mostly signature-based.** One correlation rule now exists — it
  counts distinct destinations per source over a five-minute window to separate
  control-asset enumeration from normal polling — but it is the only stateful
  detection here, and there is still no long-window behavioural baseline. The
  harness that proves it is equally narrow: the offline evaluator implements
  `value_count` and fails loudly on every other correlation type, and the benign
  baseline is single-event, so correlation false positives are covered only by
  the negative windows in the rule's own fixture.
- **Encrypted channels.** OPC UA service bodies are only visible on `None`/`Sign`
  channels; `SignAndEncrypt` yields metadata but no service. The S7comm decoder
  handles classic S7comm only, not S7comm Plus.
- **The emulation plan is small** — two steps and four expectations — so the
  detection-rate and MTTD figures are directional, not a benchmark.

## If I continued

1. Add a broader tactic spread (Impact, Evasion, C2, Initial Access) rather than
   deepening the same columns.
2. Add more stateful detections. The first one landed — control-asset
   enumeration — along with the fixture format and evaluator it needed; the next
   candidates are setpoint drift over time and an engineering-workstation change
   window, both of which need a longer window than the current evaluator's
   sliding count.
3. Grow the benign baseline from real lab traffic so false-positive rate becomes
   meaningful.
4. Run the emulation in CI against an ephemeral lab and publish live metrics.
5. Add Wazuh as a conversion target.
