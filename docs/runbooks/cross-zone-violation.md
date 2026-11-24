# Runbook: Cross-Zone Violation

| Field | Value |
| :-- | :-- |
| Rule | `ot_firewall_cross_zone_violation` |
| Technique | T0886 — Lateral Movement |
| Severity | high |
| Data source | `ot_firewall/iptables` |
| Catalogue | `metadata/detection-catalog.yaml` |
| Status | stable |

## What it means

An enterprise-zone host sent industrial protocol traffic to the control zone and
the zone firewall dropped it. A healthy Purdue segmentation has no direct Level
4/5 → Level 1 path, so either an asset is misconfigured, a host is trying to
pivot, or the firewall is the only thing standing between the enterprise and a
controller.

A single drop is a policy violation. A burst from one source across several
destinations or ports is a host actively looking for a way in.

## First 5 minutes

1. Identify the source and destination from the alert (`src_ip`, `dst_ip`,
   `dst_port`, `proto`).
2. Check whether the flow was accepted or dropped. This rule only covers the
   dropped path; an accepted path is the `ot_firewall_enterprise_control_service`
   rule and is more urgent.
3. Look up both hosts in the asset inventory. An unknown source is a stronger
   signal than a known corporate workstation.
4. Check the change calendar. A documented maintenance path can explain one
   flow, not a sweep.
5. Ask the enterprise owner whether the source is expected to reach OT at all.

## Validate before escalating

- Confirm the source is not the zone gateway performing an ICMP health check;
  ICMP is excluded by the rule.
- Confirm the destination port is an industrial service (102, 502, 4840, 20000),
  not an unrelated enterprise port.
- Check whether the same source appears in `ot_flow` with denied or reset
  connections. A single dropped packet is noise; repeated attempts are a
  campaign.

## Containment (OT-safe)

1. Do not power off a PLC or the control switch to stop the traffic.
2. Block the source at the gateway's forward chain, not at the controller.
3. Preserve the flow records and a packet capture around the event.
4. If the source is a compromised enterprise host, isolate it through the
   enterprise process while the OT block stays in place.

## False positives and tuning

- The gateway's own reachability check is normally ICMP and is excluded.
- An authorised monitoring collector or backup path may be documented; add it to
  the conduit policy, not to a permanent suppression.
- A newly zoned subnet will look like an undeclared path until the policy is
  updated. Fix the policy; do not silence the rule.

## Close out

- Record the source, destination, port and decision in the incident ticket.
- If the flow was a misconfiguration, update
  `metadata/ot-conduit-policy.yaml` and re-run `make conduit-check`.
- If it was malicious, preserve the evidence and rotate any credential the
  source could reach.

## Related rules

- `ot_firewall_enterprise_control_service` — the same path, but accepted.
- `ot_firewall_control_zone_egress` — control-to-enterprise egress.
- `ot_firewall_control_port_scan` — one source probing several control ports.

## Last validated

2026-11-24.
