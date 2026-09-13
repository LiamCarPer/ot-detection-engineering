"""Minimal Suricata rule reader used for structural validation in CI.

This is not a Suricata parser. It extracts the fields this repository requires
every native rule to carry (sid, rev, msg, classtype, and an ATT&CK for ICS
metadata tag) so that native detection content is governed by the same tests as
the Sigma rules. Functional validation of the rules themselves happens in the
NDR pipeline that runs Suricata.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

HEADER_RE = re.compile(
    r"^(?P<action>alert|drop|pass|reject)\s+"
    r"(?P<proto>\S+)\s+(?P<src>\S+)\s+(?P<sport>\S+)\s+"
    r"(?P<direction>->|<>)\s+"
    r"(?P<dst>\S+)\s+(?P<dport>\S+)\s+"
    r"\((?P<options>.*)\)\s*$"
)
SID_RE = re.compile(r"(?:^|;)\s*sid\s*:\s*(\d+)\s*;")
REV_RE = re.compile(r"(?:^|;)\s*rev\s*:\s*(\d+)\s*;")
MSG_RE = re.compile(r'(?:^|;)\s*msg\s*:\s*"([^"]*)"\s*;')
CLASSTYPE_RE = re.compile(r"(?:^|;)\s*classtype\s*:\s*([^;]+?)\s*;")
METADATA_RE = re.compile(r"(?:^|;)\s*metadata\s*:\s*([^;]+?)\s*;")
ATTACK_ICS_RE = re.compile(r"attack_ics\s+([A-Za-z0-9.]+)")


@dataclass
class SuricataRule:
    source: Path
    line_number: int
    raw: str
    action: str = ""
    protocol: str = ""
    msg: str | None = None
    classtype: str | None = None
    sid: int | None = None
    rev: int | None = None
    attack_ics: list[str] = field(default_factory=list)


def _logical_lines(path: Path) -> list[tuple[int, str]]:
    lines: list[tuple[int, str]] = []
    buffer = ""
    start = 0
    for number, physical in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = physical.strip()
        if not buffer and (not stripped or stripped.startswith("#")):
            continue
        if not buffer:
            start = number
        buffer += stripped
        if buffer.endswith("\\"):
            buffer = buffer[:-1]
            continue
        lines.append((start, buffer))
        buffer = ""
    return lines


def read_rules(path: Path) -> list[SuricataRule]:
    rules: list[SuricataRule] = []
    for line_number, text in _logical_lines(path):
        rule = SuricataRule(source=path, line_number=line_number, raw=text)
        header = HEADER_RE.match(text)
        if header:
            rule.action = header.group("action")
            rule.protocol = header.group("proto")
        options = header.group("options") if header else text
        if sid := SID_RE.search(options):
            rule.sid = int(sid.group(1))
        if rev := REV_RE.search(options):
            rule.rev = int(rev.group(1))
        if msg := MSG_RE.search(options):
            rule.msg = msg.group(1)
        if classtype := CLASSTYPE_RE.search(options):
            rule.classtype = classtype.group(1)
        if metadata := METADATA_RE.search(options):
            rule.attack_ics = ATTACK_ICS_RE.findall(metadata.group(1))
        rules.append(rule)
    return rules
