# Runbook: Detection Service Stopped

**Signal:** `Detection Service Stopped` (`ot_detection_service_down`), severity
critical, technique T0881.

## What it means

A detection producer that should be running is not. The wire may still be quiet,
but the queue is blind. This is an inhibit-response event, not a routine health
warning.

## First 15 minutes

1. Confirm the producer name in the `producer` field and the last heartbeat or
   log line.
2. Check whether the stop was planned: a maintenance window, a configuration
   change, or a container restart. If planned, record the window and restore the
   producer.
3. If unplanned, treat it as possible adversary action: check the host and
   container for a stop, kill or crash, and preserve the logs before restarting.
4. Restore the producer, then confirm it is healthy and that new events are
   reaching the queue.
5. Do not trust the queue for the gap interval. Re-run the affected rules against
   the preserved capture or the raw sensor logs.

## Recovery

- A producer that restarts but does not emit should be treated as still down.
- If the producer is intentionally retired, remove its rule and catalogue entry
  in the same change; do not leave a silent gap.

## What this does not prove

The event proves a process is missing, not why. The cause is a host/container
investigation, not a network detection.
