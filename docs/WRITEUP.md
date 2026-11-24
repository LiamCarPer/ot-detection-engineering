# Building an OT detection-engineering loop

Most detection repositories are a folder of rules with a README. The hard part
of detection engineering is not writing the first rule; it is the loop around it:
what data it needs, what it looks like when it is noisy, who owns it, how it is
validated against an adversary, and how it is retired.

This repository is my attempt to make that loop explicit for OT/ICS.

## The starting point

I had a lab: a Dockerised water-treatment range with Modbus PLCs, a DNP3
outstation, an OPC UA server, an S7comm PLC, an HMI, a historian, a segmented
network and an attacker. I had a pile of Sigma rules and native Suricata rules.
What I did not have was evidence that the rules mattered.

The first honest measurements were uncomfortable:

- **17.5% coverage** and **52 benign events** was the old CV line. It was stale,
  and the benign sample was too small to mean anything.
- A **0.0 false-positive rate** on 52 hand-written events is not a claim; the
  95% upper bound is ~6.9%.
- The purple team was two steps and one run.
- The docs and the code disagreed in places.

## The loop I built

1. **Threat model and coverage.** Every rule carries an ATT&CK for ICS
   technique. Coverage is reported by tactic, with the gaps explained rather than
   padded.
2. **Telemetry.** Rust decoders for DNP3, S7comm and OPC UA; a collector for
   Suricata, Zeek, NetFlow and SNMP; a normalized contract.
3. **Detection content.** Sigma for log events, correlation for windows, native
   Suricata for protocol DPI, YARA for file/firmware content, behaviour-baseline
   and conduit rules for learned/policy conditions, and a stateful family for
   drift, change windows and per-asset protocol profiles.
4. **Validation.** Every rule has positive and negative fixtures; a separate
   held-out set reports per-rule precision/recall with Wilson intervals.
5. **Deployment.** One Sigma source converted to Loki, OpenSearch, Splunk and
   Sentinel, with SHA-256 provenance and a drift check.
6. **Adversary emulation.** A purple-team plan scored against lab alerts, with
   MITRE-label cross-checks, unexpected-alert scoring and a benign window.
7. **Operations.** A detection catalogue with owner, severity, data source,
   expected volume, runbook and validation date; a health gate that refuses a
   stable rule without them.
8. **Triage analysis.** A reproducible case study that turns 151 lab alerts into
   24 episodes and 5 operational events, and explains what to suppress and what
   not to.

## What the work found

- **151 alerts in 160 seconds** were **84.1% duplicates**. The queue was one
  enterprise pivot, one compromised EWS, one operator-workstation write, one
  credential attack and one sensor-health event. Dedupe is a detection-engineering
  problem, not an analyst failure.
- **14/14 purple-team expectations across 8 steps**, 0 unexpected alerts and a
  passing benign window. The MTTD run is separate: 4/4 at 2.45 s, `n=4`, one run.
- **66 catalogued rules, 6 stable, 12 with observed lab volume, 0 gaps.** The
  other 60 are explicitly experimental.
- **29/97 ATT&CK for ICS coverage**, deliberately. Privilege Escalation is 0/2
  because there is no host/auth telemetry; padding it with network rules would be
  dishonest.

## What went wrong

The most useful parts of the repo are the failures:

- **A T0832 Manipulation-of-View rule was withdrawn.** A rule flagging a Modbus
  response from a non-PLC source looked plausible, but the collector normalizes
  `src_ip`/`dst_ip` from the flow, not the packet direction. The rule fired on
  benign traffic. I removed it rather than special-case one producer. T0832
  stays uncovered until the contract carries a responder field.
- **The DNP3 allowlist missed the benign master.** The collector proof caught it;
  the allowlist now includes the control-side master.
- **The ingest service defaulted its API key to `change-me`** while the security
  requirements claimed no default credentials. The key is now required at startup.
- **The purple-team runner only matched `alert_type`,** so three of four lab
  MITRE labels disagreed with the plan silently. It now checks the lab label and
  fails on an undeclared mismatch.
- **Several docs were stale.** The claims register and tests now keep the
  headline numbers honest, including an explicit warning against the old
  17.5%/52-event line.

## What this is not

- Not production telemetry. The benign corpus is generated, the lab is a
  Dockerised plant, and the process baseline is a model.
- Not a 24/7 SOC. There is no on-call rota, shift handover or production queue.
- Not a malware repository. The YARA fixtures are inert; the engine is proven
  with the EICAR string assembled in memory.
- Not a full performance benchmark. The decoders and matcher are measured on a
  desktop with small example frames, not a sensor at sustained rate.

## What I would do next

The next honest improvements are in [`docs/ROADMAP.md`](ROADMAP.md): real
captured benign traffic, live purple-team runs in CI, host/auth telemetry for
Privilege Escalation, pcap replay and backpressure, and integration with the
plant's change-management system.

The repo is a portfolio, but the loop is the point. A detection is only as good
as the evidence that it fires when it should, stays quiet when it should not, and
has someone who knows how to operate it.
