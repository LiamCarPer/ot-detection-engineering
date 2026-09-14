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

## `ot_ndr` / `dnp3`

Decoded DNP3 application messages. One record per request or response, produced
by [`tools/dnp3-dpi`](../tools/dnp3-dpi) from link frames or a network capture.

| Field | Type | Description |
| :--- | :--- | :--- |
| `timestamp` | string | ISO 8601 UTC, added by the collector. |
| `direction` | string | `request` or `response`. |
| `function_code` | integer | DNP3 application function code (for example `3`, `5`, `21`). |
| `function_name` | string | Function name (for example `Direct Operate`). |
| `link_source` | integer | DNP3 link source address (the master). |
| `link_destination` | integer | DNP3 link destination address (the outstation). |
| `link_function` | integer | Link layer function code. |
| `object_group` | integer | First object group (for example `12` binary output control). |
| `object_variation` | integer | First object variation. |
| `object_count` | integer | Object count from the first header. |
| `control_code` | integer | Control code for a binary-output control object. |
| `iin` | integer | Internal indications, present on responses. |
| `transport_sequence` | integer | Transport sequence number. |
| `application_sequence` | integer | Application sequence number. |

DNP3 uses link addresses rather than IP addresses, so the allowlists in the
rules are expressed against `link_source`. A collector that also knows the
transport endpoints can add `src_ip`/`dst_ip`.
