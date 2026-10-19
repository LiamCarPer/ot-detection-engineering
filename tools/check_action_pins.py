"""Fail when a GitHub Actions ``uses:`` is not pinned to a commit SHA.

A mutable tag (``@v4``) lets the action's owner repoint it at different code, so
a compromised or abandoned action runs with the repository's credentials. Pinning
to a 40-character commit SHA removes that supply-chain path; this check runs in
the offline pre-flight so a floating tag cannot merge.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
USES_RE = re.compile(r"^\s*-?\s*uses:\s*(\S+)")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def problems() -> list[str]:
    found: list[str] = []
    for path in sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = USES_RE.match(line)
            if not match:
                continue
            reference = match.group(1).strip("\"'")
            if reference.startswith("./") or reference.startswith("docker://"):
                continue
            if "@" not in reference:
                found.append(f"{path.relative_to(REPO_ROOT)}:{number}: no version: {reference}")
                continue
            _, version = reference.rsplit("@", 1)
            if not SHA_RE.match(version):
                found.append(
                    f"{path.relative_to(REPO_ROOT)}:{number}: {reference} is not a commit SHA"
                )
    return found


def main() -> int:
    found = problems()
    if found:
        print("unpinned GitHub Actions:")
        for problem in found:
            print(f"  - {problem}")
        return 1
    print("all GitHub Actions are pinned by commit SHA")
    return 0


if __name__ == "__main__":
    sys.exit(main())
