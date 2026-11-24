# CV bullets

These are written to survive a technical interview. Every number is scoped, and
the limits are stated rather than hidden.

## Primary bullets

- **Built a detection-as-code loop for OT/ICS**: 66 catalogued rules across
  Sigma, correlation, YARA, native Suricata, stateful, behaviour-baseline and
  conduit families, covering **29 ATT&CK for ICS techniques** with
  intentionally documented gaps.
- **Validated detection behaviour against a real-endpoint lab**: **14/14
  purple-team expectations across 8 steps**, 0 unexpected alerts and a passing
  benign window on the 2026-11-24 replay; separately, **4/4 at 2.45 s mean MTTD**
  on the 2026-09-13 run (`n=4`, one run).
- **Turned a real alert flood into operational events**: analyzed **151 lab
  alerts in 160 seconds** into **24 episodes and 5 operational events**
  (84.1% duplicate reduction), with the suppression and escalation decisions
  documented.
- **Added operational ownership**: **66 rules catalogued**, **6 stable rules with
  runbooks, observed volume and validation dates**, 0 catalogue gaps, and 60
  experimental rules explicitly flagged.
- **Measured the pipeline instead of guessing**: decoders at **11–23M
  frames/s** with **p99 45–218 ns per frame**; offline replay at **~3,400
  events/s** through 24 rules with 0 benign matches, on recorded hardware.

## Supporting bullets

- Built **dependency-free Rust decoders** for DNP3 (CRC-16/DNP validation),
  S7comm and OPC UA, with truncation/mutation robustness tests and a
  decoder-to-rule proof.
- Converted one Sigma source into **Loki, OpenSearch, Splunk and Sentinel**
  queries with SHA-256 provenance and a CI drift check.
- Rendered the rules in a **Malcolm pipeline** alongside 59,188 default rules
  and in a live Loki stack; 11 of the 13 lab-exercised rules fire on live traffic.
- Added a **held-out evaluation set**: 48/48 single-event positives, 12/12
  correlation windows and 8/8 YARA artifacts, with Wilson intervals and a
  fixture-leakage guard.

## Scope footnote

The lab is a Dockerised water-treatment range, not a production plant. The benign
corpus and the stateful baselines are generated or small committed samples, not
field telemetry. The purple-team coverage run has alert timestamps but not action
start timestamps, so its MTTD is not reported. The 2.45 s MTTD is `n=4`, one run.
