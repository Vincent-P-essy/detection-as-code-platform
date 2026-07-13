#!/usr/bin/env python3
"""Optionally compare vendored integration bytes with an explicit upstream directory."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from detection_platform.bundle import default_bundle_root  # noqa: E402
from detection_platform.corpus import verify_provenance  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    args = parser.parse_args()
    result = verify_provenance(default_bundle_root(), args.source)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
