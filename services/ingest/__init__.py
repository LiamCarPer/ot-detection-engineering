"""Telemetry ingest and AI-assisted triage service.

This is the product's HTTP surface: a schema-validated, authenticated, rate-limited
endpoint for normalized telemetry, and a triage endpoint that treats the model as
untrusted. It is deliberately small so its security tests describe every path.
"""
