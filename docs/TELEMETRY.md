# Telemetry contracts

Detections are only as reliable as the events they run on. This document defines
the normalized event contracts the rules in `rules/sigma` expect. Normalization
happens before the detection layer, in the collector or the NDR pipeline, so the
rules stay readable and testable.

Each contract is identified by the Sigma `logsource` (`product` / `service`) that
selects it.

## `ot_ndr` / `modbus`

Decoded Modbus/TCP transactions. One record per request or response.

| Field | Type | Description |
| :--- | :--- | :--- |
| `timestamp` | string | ISO 8601 UTC. |
| `direction` | string | `request` or `response`. |
| `function_code` | integer | Modbus function code (for example `6`, `16`, `43`). |
| `src_ip` | string | Source address. |
| `dst_ip` | string | Destination address. |
| `unit_id` | integer | Modbus unit identifier. |
| `register` | integer | Starting register address for data operations. |
| `value` | integer | Written value for write operations. |
| `exception_code` | integer | Exception code for exception responses. |

Typical producers: Zeek `modbus.log`, Suricata `eve.json` Modbus events, or a
commercial NDR platform. The `direction` field replaces the ambiguity of
inferring request/response from the TCP port.

## `ot_firewall` / `iptables`

Zone firewall decisions from the gateway.

| Field | Type | Description |
| :--- | :--- | :--- |
| `timestamp` | string | ISO 8601 UTC. |
| `action` | string | `ACCEPT`, `DROP`, or `REJECT`. |
| `proto` | string | `TCP`, `UDP`, `ICMP`. |
| `src_zone` | string | Source Purdue zone label (`it`, `dmz`, `ops`, `supervisory`, `control`). |
| `dst_zone` | string | Destination Purdue zone label. |
| `src_ip` | string | Source address. |
| `dst_ip` | string | Destination address. |
| `dst_port` | integer | Destination port. |

The zone labels come from interface-to-zone mapping on the gateway. The raw
`iptables` log line is parsed into these fields by the collector.

## `ot_process` / `safety_monitor`

Events from the physics-aware process safety monitor.

| Field | Type | Description |
| :--- | :--- | :--- |
| `timestamp` | string | ISO 8601 UTC. |
| `event_type` | string | `process_safety_violation` or `process_update`. |
| `asset` | string | Logical asset name (for example `plc_intake`). |
| `register` | integer | Register targeted by the command. |
| `value` | integer | Commanded value. |
| `tank_level_pct` | number | Observed process state used for the safety decision. |
| `actor` | string | Source that issued the command. |
| `response` | string | `none` or `auto_mitigated`. |

`response` is an enum rather than a boolean because not every conversion target
can express boolean values; using a string keeps the rule portable across
backends.
