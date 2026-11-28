# Plant threat model

`metadata/plant-threat-model.yaml` is the plant-level model: the zones, the
critical assets, six plausible adversary paths, the detections that cover them
and the gaps the plant owner still owns. It is deliberately separate from
`metadata/threat-model.yaml`, which covers the repository as a software product.

## Paths

| Path | Entry | Target | Detections | Owner gap |
| :-- | :-- | :-- | :-- | :-- |
| Enterprise to control | IT | Intake PLC | Firewall cross-zone, S7 download, process safety | No VPN identity telemetry; firewall is a model |
| Insider engineering client | Ops | OPC UA server | DNP3 control, OPC UA write, S7 download, change window | Allowlisted source can be abused; no low-and-slow baseline |
| Compromised HMI | Supervisory | Intake PLC | Process safety, process envelope, change window | Approved writer; no EDR |
| Enterprise ransomware | IT | Historian | Large transfer, enterprise-control service | No host/backup telemetry |
| DMZ/bastion | DMZ | EWS | Firewall cross-zone | No bastion/MFA/vendor identity |
| Firmware supply chain | Ops | Intake PLC | YARA firmware, S7 download, PLC integrity | No signing or golden-image inventory |

## What this changes

It makes the plant assumptions reviewable and gives every ATT&CK tag a path to
belong to. It does not turn the lab into a plant: the owner gaps are listed
rather than filled with simulated evidence. The tests check that every zone and
asset exists in the inventory, every technique is in the pinned ICS catalogue,
and every detection path exists. A detection that is listed without a committed
rule fails the test.

## Review trigger

Review this model when an asset is added or re-IPed, a conduit changes, a new
remote-access path is introduced, or a rule is retired. The asset inventory and
allowlists are generated from the same inventory; the threat model is the
narrative check on them.
