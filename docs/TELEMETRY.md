# Telemetry contracts

Detections are only as reliable as the events they run on. This document defines
the normalized event contracts the rules in `rules/sigma` expect. Normalization
happens before the detection layer, in the collector or the NDR pipeline, so the
rules stay readable and testable.

Each contract is identified by the Sigma `logsource` (`product` / `service`) that
selects it.

## Producers

- **`collector/`** normalizes Suricata `eve.json` and Zeek `modbus.log` /
  `dnp3.log` into these events, attaches the `product` / `service` routing and an
  ISO 8601 UTC timestamp, and validates every event against
  `metadata/telemetry.schema.json`. `make collector-check` proves the output
  fires the rules.
- **`tools/dnp3-dpi`, `tools/s7comm-dpi`, `tools/opcua-dpi`** emit the raw
  application-layer events; the collector or the pipeline attaches the routing
  fields.

Sensors differ in what they can see, so which fields are present depends on the
source. A field the source cannot see is **omitted, never guessed**, so a rule
can distinguish "the master was authorized" from "the master was not visible".
The per-sensor field matrix is in `collector/README.md`.

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

## `ot_ndr` / `s7comm`

Decoded classic S7comm jobs and responses, produced by
[`tools/s7comm-dpi`](../tools/s7comm-dpi) from TPKT/COTP frames on TCP/102.

| Field | Type | Description |
| :--- | :--- | :--- |
| `timestamp` | string | ISO 8601 UTC, added by the collector. |
| `direction` | string | `request` (ROSCTR Job) or `response` (Ack/Ack-Data). |
| `function_code` | integer | S7 function code (for example `4` Read Var, `26` Request Download, `41` PLC Stop). |
| `function_name` | string | Function name. |
| `rosctr` | integer | Message type (`1` Job, `3` Ack-Data). |
| `pdu_reference` | integer | PDU reference. |
| `parameter_length` | integer | Parameter block length. |
| `data_length` | integer | Data block length. |
| `cotp_type` | integer | COTP PDU type (`240` for data transfer). |

S7comm carries no source identity, so the "unauthorized write" detection is
expressed at the network layer against the client IP, while the
protocol-intrinsic detections (program download/upload, mode change) run over
these events.

## `ot_ndr` / `opcua`

Decoded OPC UA messages, produced by [`tools/opcua-dpi`](../tools/opcua-dpi)
from TCP/4840 traffic.

| Field | Type | Description |
| :--- | :--- | :--- |
| `timestamp` | string | ISO 8601 UTC, added by the collector. |
| `message_type` | string | `HEL`, `ACK`, `ERR`, `RHE`, `OPN`, `MSG` or `CLO`. |
| `chunk_type` | string | `F` (final), `C` (intermediate) or `A` (abort). |
| `secure_channel_id` | integer | Secure channel id, on OPN/MSG/CLO. |
| `security_policy_uri` | string | Security policy from OPN (for example `None`). |
| `token_id` | integer | Symmetric token id, on MSG/CLO. |
| `sequence_number` | integer | Sequence number. |
| `request_id` | integer | Request id. |
| `service_id` | integer | Service NodeId identifier (for example `673` WriteRequest). |
| `opcua_service` | string | Service name, present only on plaintext bodies. |
| `direction` | string | `request` or `response`, derived from the service name. |

The service is only present when the body is not encrypted. `Sign` keeps the body
in clear text; `SignAndEncrypt` does not, so those messages carry the header
fields with no `opcua_service`.

## `ot_flow` / `flow`

Flow records, from a NetFlow/IPFIX exporter or Zeek's `conn.log`, produced by the
collector's `netflow` and Zeek `conn` sources. Flow is the fallback visibility
where DPI cannot see the payload (encrypted or unknown protocols).

| Field | Type | Description |
| :--- | :--- | :--- |
| `timestamp` | string | ISO 8601 UTC. |
| `src_ip` / `dst_ip` | string | Flow endpoints. |
| `src_port` / `dst_port` | integer | Flow ports. |
| `proto` | string | Transport protocol. |
| `app_protocol` | string | Application protocol the sensor identified (for example `modbus`), when known. |
| `bytes` / `packets` | integer | Totals across both directions. |
| `duration` | number | Flow duration in seconds. |
| `flow_state` | string | Sensor flow state (for example Zeek `SF`). |

## `ot_snmp` / `snmp`

SNMP traps or poll results from an OT network device, produced by the collector's
`snmp` source. This is the device-availability and configuration layer.

| Field | Type | Description |
| :--- | :--- | :--- |
| `timestamp` | string | ISO 8601 UTC. |
| `device` / `src_ip` | string | The reporting device. |
| `event_type` | string | `interface_down`, `interface_up`, `device_restart`, `config_change`, `heartbeat`. |
| `oid` | string | Object identifier, when the source carries one. |
| `snmp_value` | string | The value as a string; SNMP values are not always numeric. |
| `severity` | string | Source severity, when present. |
