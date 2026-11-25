# Roadmap and deliberate gaps

The repository is a portfolio, not a product. This page records what I would do
next and what I deliberately did not do.

## Next

1. **Capture real benign traffic.** Replace the generated benign corpus with a
   24-hour lab capture, reported separately from the generated set. The current
   1,000-event corpus is a statistical bound, not a field baseline.
2. **Run the purple team in CI.** The 2026-11-24 evidence is a replay of the
   lab's alert labels. An ephemeral lab in CI would make 8-step execution and
   MTTD reproducible on every commit.
3. **Add host/auth telemetry.** Privilege Escalation is 0/2 because there is no
   host or authentication source. A Sysmon/auth-log collector would close it
   honestly.
4. **Build a pcap replay and backpressure test.** The current performance
   numbers are decoder and matcher microbenchmarks. The next step is a live
   sensor at sustained rate with a slow consumer and a full queue.
5. **Integrate the change calendar.** Replace the committed YAML with a read-only
   feed from the change-management system; the detection logic does not change.
6. **Add repo rules for the lab-only detections.** HMI login failure, C2 beacon
   and OT port scan are emitted by the lab but not scored by this repo.
7. **Add Wazuh as a conversion target.** It is the next platform in the
   deployment matrix.

## Deliberately not done

- **Coverage padding.** Tagging untested rules to raise 32/97 would destroy the
  repo's only real claim: every rule is validated.
- **Real malware.** The YARA family uses inert synthetic artifacts and the
  EICAR test string. Public-sample analysis in an isolated lab is the credible
  next step if that becomes the goal.
- **A live LLM provider.** The AI triage path is a tested stub; a live provider
  adds secrets and network without adding a detection-engineering signal.
- **A 24/7 SOC simulation.** There is no on-call rota, shift handover or
  production incident load; pretending otherwise would be dishonest.
- **A commercial BAS deployment.** AttackIQ is commercial; the lab uses a
  deterministic harness and an optional Caldera profile. AttackIQ Academy is
  training, not product experience.

## How to judge the repo

Read [`docs/CLAIMS.md`](CLAIMS.md) and [`docs/DEMO.md`](DEMO.md) together. The
demo is the short path through the work; the claims register is the evidence
behind every number. If a number is not in the claims register, do not quote it.

## Current implementation

Implemented: detection-as-code pipeline, OT Sigma rules, native protocol DPI for
Modbus/TCP, DNP3, OPC UA and S7comm, stateful correlation rules for
control-asset enumeration, proxy fan-out, port sweeps, register enumeration,
OPC UA browsing and exception floods, a stateful detection family, multi-platform
conversion (Loki, OpenSearch, Splunk SPL, Sentinel KQL), installable deployment
bundles, Suricata validation over captures and in a Malcolm pipeline, ATT&CK for
ICS coverage, adversary emulation, a detection catalogue and health report, and
performance evidence. The pipeline, conversion, tests, coverage, all-family
false positives, catalogue, case study and performance evidence run in CI in
read-only mode; the container, Malcolm and live-lab validations run locally and
their committed evidence is guarded by tests.

## Integration status

- [x] Install the Suricata ruleset into
      [OT-NDR-Malcolm-Pipeline](https://github.com/LiamCarPer/OT-NDR-Malcolm-Pipeline)
      and run it with Malcolm's own Suricata image and default ruleset.
- [x] Install the Loki ruler bundle into
      [OT-Security-Lab](https://github.com/LiamCarPer/OT-Security-Lab) and confirm
      the DNP3, OPC UA, S7comm, firewall and process rules on live traffic.
- [ ] Run emulation against the live lab in CI and publish live metrics.
- [ ] Add Wazuh as a conversion target.

## Protocol coverage

- [x] Modbus/TCP — native Suricata function-code DPI.
- [x] DNP3 — native Suricata function/object DPI plus a Rust application-layer
      decoder and Sigma rules.
- [x] S7comm — native Suricata function-code DPI plus a Rust application-layer
      decoder and Sigma rules.
- [x] OPC UA — native Suricata TCP message-header DPI plus a Rust service
      decoder and Sigma rules.
- [ ] PROFINET (layer-2 / DCE-RPC; needs non-IP rule hooks).
