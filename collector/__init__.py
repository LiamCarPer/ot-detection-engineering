"""Normalize standard OT sensor output into the repository's telemetry contract.

The Sigma rules run on a documented contract (docs/TELEMETRY.md), not on a
vendor's native format. This package is the producer: it reads Suricata
``eve.json`` or Zeek logs and emits contract events with the routing fields the
rules expect. ``tools/collector_check.py`` proves the output fires the rules.
"""
