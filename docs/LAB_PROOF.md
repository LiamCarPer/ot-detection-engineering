# One-command lab proof

The individual lab checks each write their own evidence. `make lab-proof` runs
them in dependency order and records the operator's view: what ran, what passed
and what was skipped.

| Step | What it proves | Evidence |
| :-- | :-- | :-- |
| `sensor-health` | The watchdog rule fires in the live ruler | `deploy/evidence/lab-health/` |
| `live-rules` | Every rule the lab exercises fires live | `deploy/evidence/lab-loki/` |
| `live-purple` | The repository rules fire for the emulation steps | `deploy/evidence/purple-live/` |
| `engine-parity` | Converted SPL/PPL/KQL select the matcher's events | `deploy/evidence/engine-parity/` |
| `benign-capture` | Every network family over the saved capture | `deploy/evidence/benign-lab/` |

## The capture guard

A 24-hour benign capture must not see emulation traffic. `tools/lab_proof.py`
checks whether `benign_capture.py` is running, or whether the PCAP was written
in the last five minutes, and **skips the attack steps and the capture analysis**
when it is. Analysing a growing PCAP would report a partial window as if it were
the full run.

`make lab-proof-dry-run` prints the plan and the skip decision without running
anything. The live proof writes to `deploy/evidence/lab-proof/`, which is a local
run artifact and intentionally not committed; the canonical purple evidence is
the stable 12/12 snapshot under `deploy/evidence/purple-live/`.

## Scheduling

The repository has no registered self-hosted runner, so the scheduled variant is
not enabled: a `runs-on: [self-hosted, ot-lab]` job would queue forever. The
honest arrangement is a local run with the evidence committed, and it is what
`make lab-proof` is for. If a runner is registered later, the same command is the
job body.

## Limits

- Live steps need the lab containers and the Loki ruler; the command fails
  loudly when they are absent.
- One run, not a soak. A flaky step is visible as a failed row, not retried
  silently.
- The benign-capture step replays a saved PCAP over Suricata and Zeek, not the
  production sensor path.
