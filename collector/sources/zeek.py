"""Zeek ``modbus.log`` / ``dnp3.log`` -> telemetry contract.

Zeek's OT analyzers log the function, direction and endpoints, but not register
values (Modbus) or link addresses (DNP3). Those fields are omitted rather than
invented, which matters: the DNP3 control rule applies a master allowlist on
``link_source``, so a Zeek-only deployment cannot evaluate it and must identify
the master another way. See ``collector/README.md``.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

from collector.contract import event

PRODUCT = "ot_ndr"

# Zeek logs function names; the contract uses the numeric code (docs/TELEMETRY.md).
MODBUS_FUNCTIONS: dict[str, int] = {
    "READ_COILS": 1,
    "READ_DISCRETE_INPUTS": 2,
    "READ_HOLDING_REGISTERS": 3,
    "READ_INPUT_REGISTERS": 4,
    "WRITE_SINGLE_COIL": 5,
    "WRITE_SINGLE_REGISTER": 6,
    "READ_EXCEPTION_STATUS": 7,
    "DIAGNOSTICS": 8,
    "GET_COMM_EVENT_COUNTER": 11,
    "GET_COMM_EVENT_LOG": 12,
    "WRITE_MULTIPLE_COILS": 15,
    "WRITE_MULTIPLE_REGISTERS": 16,
    "REPORT_SERVER_ID": 17,
    "READ_FILE_RECORD": 20,
    "WRITE_FILE_RECORD": 21,
    "MASK_WRITE_REGISTER": 22,
    "READ_WRITE_MULTIPLE_REGISTERS": 23,
    "READ_FIFO_QUEUE": 24,
    "ENCAPSULATED_INTERFACE_TRANSPORT": 43,
}

DNP3_FUNCTIONS: dict[str, int] = {
    "CONFIRM": 0,
    "READ": 1,
    "WRITE": 2,
    "SELECT": 3,
    "OPERATE": 4,
    "DIRECT_OPERATE": 5,
    "DIRECT_OPERATE_NR": 6,
    "IMMED_FREEZE": 7,
    "IMMED_FREEZE_NR": 8,
    "FREEZE_CLEAR": 9,
    "FREEZE_CLEAR_NR": 10,
    "FREEZE_AT_TIME": 11,
    "FREEZE_AT_TIME_NR": 12,
    "COLD_RESTART": 13,
    "WARM_RESTART": 14,
    "INITIALIZE_DATA": 15,
    "INITIALIZE_APPL": 16,
    "START_APPL": 17,
    "STOP_APPL": 18,
    "SAVE_CONFIG": 19,
    "ENABLE_UNSOLICITED": 20,
    "DISABLE_UNSOLICITED": 21,
    "ASSIGN_CLASS": 22,
    "DELAY_MEASURE": 23,
    "RECORD_CURRENT_TIME": 24,
    "OPEN_FILE": 25,
    "CLOSE_FILE": 26,
    "DELETE_FILE": 27,
    "GET_FILE_INFO": 28,
    "AUTHENTICATE_FILE": 29,
    "ABORT_FILE": 30,
    "ACTIVATE_CONFIG": 31,
    "AUTHENTICATE_REQ": 32,
}

UNSET = "-"


def _rows(path: Path) -> Iterator[dict[str, str]]:
    """Yield rows from a Zeek tab-separated log, using its ``#fields`` header."""
    separator = "\t"
    unset = UNSET
    fields: list[str] | None = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("#separator"):
            raw = line[len("#separator") :].strip()
            separator = "\t" if raw == "\\x09" else raw
        elif line.startswith("#unset_field"):
            unset = line[len("#unset_field") :].strip()
        elif line.startswith("#fields"):
            fields = line[len("#fields") :].lstrip().split(separator)
        elif not line or line.startswith("#"):
            continue
        elif fields is not None:
            yield {
                name: ("" if value == unset else value)
                for name, value in zip(fields, line.split(separator), strict=False)
            }


def events(paths: Iterable[Path]) -> Iterator[dict[str, Any]]:
    """Yield contract events from Zeek ``modbus.log`` and ``dnp3.log`` files."""
    for path in paths:
        name = Path(path).name
        for row in _rows(Path(path)):
            if "modbus" in name:
                converted = _modbus(row)
            elif "dnp3" in name:
                converted = _dnp3(row)
            else:
                continue
            if converted is not None:
                yield converted


def _modbus(row: dict[str, str]) -> dict[str, Any] | None:
    code = MODBUS_FUNCTIONS.get(row.get("func", ""))
    if code is None:
        return None
    return event(
        PRODUCT,
        "modbus",
        float(row["ts"]),
        direction=_direction(row.get("pdu_type", "")),
        function_code=code,
        unit_id=_int(row.get("unit")),
        src_ip=row.get("id.orig_h"),
        dst_ip=row.get("id.resp_h"),
    )


def _dnp3(row: dict[str, str]) -> dict[str, Any] | None:
    request = row.get("fc_request", "")
    reply = row.get("fc_reply", "")
    if request:
        direction, name = "request", request
    elif reply:
        direction, name = "response", reply
    else:
        return None
    code = DNP3_FUNCTIONS.get(name)
    if code is None:
        return None
    return event(
        PRODUCT,
        "dnp3",
        float(row["ts"]),
        direction=direction,
        function_code=code,
        # Zeek's dnp3.log does not carry link source/destination addresses.
        src_ip=row.get("id.orig_h"),
        dst_ip=row.get("id.resp_h"),
    )


def _direction(pdu_type: str) -> str | None:
    if pdu_type == "REQ":
        return "request"
    if pdu_type == "RESP":
        return "response"
    return None


def _int(value: str | None) -> int | None:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
