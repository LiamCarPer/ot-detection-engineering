# Runbook: OPC UA Address-Space Browse

| Field | Value |
| :-- | :-- |
| Rule | `ot_opcua_browse_request` |
| Technique | T0888 — Remote System Information Discovery |
| Severity | medium |
| Data source | `ot_ndr/opcua` |
| Catalogue | `metadata/detection-catalog.yaml` |
| Status | stable |

## What it means

An OPC UA client issued a Browse or BrowseNext request. Browsing walks the address
space to enumerate nodes, tags and structures; it is the discovery step before a
write, a method call or a targeted collection. A client that browses once on
connect is normal; a sustained browse is point-and-tag identification.

Only plaintext (`None`/`Sign`) channels expose the service, so this rule cannot
see `SignAndEncrypt` traffic.

## First 5 minutes

1. Read `secure_channel_id`, `request_id`, `service_id` and `src_ip` if present.
2. Identify the client and the OPC UA server.
3. Check whether the client is a known HMI, historian or engineering tool.
4. Count the browse requests from the same session in the last five minutes.
5. Check whether the same session also wrote a node or called a method.

## Validate before escalating

- A client populating its address space on connect is expected.
- An asset inventory or commissioning tool may browse every node once.
- A burst from an unexpected host, especially followed by a write or call, is
  enumeration.
- Correlate with `ot_opcua_node_enumeration` for the windowed view.

## Containment (OT-safe)

1. Do not restart the OPC UA server.
2. If the client is unauthorized, block it at the gateway or revoke its session.
3. Preserve the session metadata and the browse requests.
4. If a write or call followed, treat it as a control-path event and follow the
   relevant runbook.

## False positives and tuning

- A client that reconnects for every request falls below the per-session count;
  use the first-order browse rule for that case.
- An authorised inventory tool should be documented, not permanently suppressed.
- Encrypted channels are out of scope; a network rule cannot see the service.

## Close out

- Record the client, session, request count and any follow-on write or call.
- If unauthorized, review the client host and rotate its OPC UA credentials.
- If authorized, add the client to the inventory and document the browse.

## Related rules

- `ot_opcua_node_enumeration` — the windowed browse burst.
- `ot_opcua_write_request` — the write that may follow.
- `ot_opcua_method_call` — the execution path that may follow.

## Last validated

2026-11-24.
