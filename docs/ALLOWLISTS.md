# Detection allowlists

Every protocol rule that excludes an approved source carries an IP literal:
`not filter_authorized_writer`, `[!172.23.0.20]`, and so on. Those literals are
policy. When a host changes role, the inventory changes, and the rule keeps
trusting the old address unless something forces a review.

`metadata/allowlists.yaml` is that something. It names each authorized set, the
inventory roles that may belong to it, and the Sigma/native detections bound to
it. `tools/allowlists.py` resolves the members against `metadata/assets.yaml`,
checks that every exclusion in a rule is exactly a declared set, and writes
`metadata/allowlists.generated.yaml` with the resolved role, zone and
criticality for review and for the site's firewall or EDR.

## Sets

| Set | Members | Meaning |
| :-- | :-- | :-- |
| `modbus_approved_writers` | HMI | The only standing Modbus writer; engineering changes use the change calendar |
| `modbus_approved_block_readers` | HMI, L2 historian collector | Large block reads are polling, not enumeration; the gateway is not in this set |
| `modbus_approved_process_readers` | Gateway/IDS, HMI, L2 historian collector | The gateway's single-register HR5 poll plus HMI/historian process reads |
| `dnp3_approved_masters` | Engineering client | A second master is a rogue-master finding |
| `opcua_approved_writers` | HMI, EWS | Interactive OPC UA clients; the engineering client's OPC UA use is the insider path |
| `opcua_approved_connectors` | Engineering client | Allowed to open a channel, not to write |
| `s7comm_approved_clients` | Engineering client | Connection allowlist; downloads still go to the change window |

## What the check enforces

- Every member exists in the inventory and has one of the declared roles.
- Every Sigma `filter_*` selection and every native `[!ip]` matches exactly the
  set bound to it; an unbound exclusion or a set difference fails the build.
- Every declared binding produces a rule exclusion, so a stale entry fails.
- No allowlist is declared without a consumer.

## Limits

- Allowlists are a lab policy, not a universal one. A plant's approved writers
  and masters are site-specific.
- The DNP3 link-address allowlist (link addresses 1 and 2) is a protocol
  identity, not an IP; it lives in the rule and the runbook, not here.
- The S7 Sigma rule deliberately has no IP allowlist: every program download is
  an event, and the change-window rule decides whether it was approved. The
  native S7 rule keeps a connection allowlist, which is a different question.
