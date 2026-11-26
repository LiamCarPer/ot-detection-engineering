"""Independent tank mass balance for the process-safety detections.

The lab's original safety monitor shadows the tank level that the PLC reports.
That is useful, but it trusts the sensor: a controller or an insider that pins
the level register also blinds the monitor. This service estimates the level
from the flows instead:

    level(t + dt) = level(t) + (inlet_flow - outlet_flow) / capacity * dt

The estimate never reads the reported level. The emitted event carries both, so
a divergence is visible, and the safety envelope is evaluated on the estimate.

The same module contains a small plant model used by the offline check. It is a
model, not plant data, and the check says so. Run against a live Modbus source,
the estimator consumes the valve/pump command plus the flow registers and does
not need the PLC's level at all.

Usage (simulation):
    python services/process/mass_balance.py --scenario unsafe
    python services/process/mass_balance.py --scenario spoof --jsonl out.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

HIGH_LEVEL = 90.0
DIVERGENCE_LIMIT = 15.0
COMMAND_TIME = 55.0


@dataclass
class Plant:
    """The simulated process: a tank with a measured inlet and outlet flow."""

    level: float = 20.0
    capacity_pct_per_m3: float = 10.0
    inlet_m3_per_s: float = 0.25
    outlet_m3_per_s: float = 0.10
    valve_open: int = 0
    interlock_tripped: bool = False
    reported_offset: float = 0.0

    def step(self, dt: float, force_valve: int | None = None) -> tuple[float, float, float]:
        """Advance physics and return (reported level, inlet flow, outlet flow)."""
        if force_valve is None:
            # Normal level control: fill when low, and the SIS closes above 95%.
            if self.level < 20.0:
                self.valve_open = 1
            if self.level >= 95.0:
                self.valve_open = 0
                self.interlock_tripped = True
            self.interlock_tripped = self.level >= 95.0
        else:
            self.valve_open = force_valve
            self.interlock_tripped = False
        inlet = self.inlet_m3_per_s if self.valve_open else 0.0
        outlet = self.outlet_m3_per_s
        self.level += (inlet - outlet) / self.capacity_pct_per_m3 * 100.0 * dt
        self.level = max(0.0, min(100.0, self.level))
        reported = max(0.0, min(100.0, self.level + self.reported_offset))
        return reported, inlet, outlet


@dataclass
class MassBalance:
    """Estimate the level from measured flows, never from the reported level."""

    level: float = 20.0
    capacity_pct_per_m3: float = 10.0
    inlet_flow: float = 0.0
    outlet_flow: float = 0.0

    def update(self, inlet_flow: float, outlet_flow: float, dt: float) -> float:
        self.inlet_flow = inlet_flow
        self.outlet_flow = outlet_flow
        self.level += (inlet_flow - outlet_flow) / self.capacity_pct_per_m3 * 100.0 * dt
        self.level = max(0.0, min(100.0, self.level))
        return self.level


def _stamp(start: datetime, seconds: float) -> str:
    return (start + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def simulate(
    scenario: str,
    duration: float = 120.0,
    dt: float = 1.0,
    start: datetime | None = None,
) -> list[dict[str, Any]]:
    """Run a scenario and return normalized process events."""
    if scenario not in {"normal", "unsafe", "spoof"}:
        raise ValueError(f"unknown scenario {scenario!r}")
    start = start or datetime(2026, 11, 25, 6, 0, 0, tzinfo=UTC)
    plant = Plant()
    estimator = MassBalance()
    events: list[dict[str, Any]] = []
    commanded = False
    for step in range(int(duration / dt)):
        now = step * dt
        force: int | None = None
        if scenario == "spoof" and now >= 40.0:
            # The reported level is pinned; the flows still measure the truth.
            plant.reported_offset = 40.0 - plant.level
        if scenario in {"unsafe", "spoof"} and now >= COMMAND_TIME:
            # An external write opens the inlet regardless of the level. The
            # automatic fill controller is not a command and never alerts.
            force = 1
            if not commanded and estimator.level >= HIGH_LEVEL:
                commanded = True
        reported, inlet, outlet = plant.step(dt, force_valve=force)
        estimated = estimator.update(inlet, outlet, dt)
        divergence = abs(estimated - reported)
        common = {
            "timestamp": _stamp(start, now),
            "product": "ot_process",
            "service": "safety_monitor",
            "producer": "mass_balance",
            "asset": "PLC-01",
            "event_type": "process_update",
            "tank_level_pct": round(estimated, 2),
            "reported_level_pct": round(reported, 2),
            "divergence_pct": round(divergence, 2),
            "inlet_valve": plant.valve_open,
            "inlet_flow": round(inlet, 3),
            "outlet_flow": round(outlet, 3),
            "response": "none",
            "severity": "info",
        }
        events.append(common)
        if commanded and not any(
            event["event_type"] == "process_safety_violation" for event in events
        ):
            events.append(
                {
                    **common,
                    "event_type": "process_safety_violation",
                    "severity": "critical",
                    "actor": "external-write",
                    "register": 0,
                    "value": 1,
                    "description": (
                        "External open command with the estimated tank level at or "
                        f"above {HIGH_LEVEL:.0f}%"
                    ),
                }
            )
    return events



def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", default="normal", choices=["normal", "unsafe", "spoof"])
    parser.add_argument("--duration", type=float, default=120.0)
    parser.add_argument("--jsonl", default=None)
    args = parser.parse_args(argv)
    events = simulate(args.scenario, args.duration)
    if args.jsonl:
        Path(args.jsonl).write_text(
            "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
            encoding="utf-8",
        )
        print(f"wrote {len(events)} events to {args.jsonl}")
    else:
        for event in events:
            if event["event_type"] == "process_safety_violation":
                print(json.dumps(event, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
