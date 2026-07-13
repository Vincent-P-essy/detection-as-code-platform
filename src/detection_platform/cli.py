"""Command-line interface for validation, replay, export, and local serving."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path
from typing import Sequence

from .api import serve
from .audit import verify_audit_chain
from .bundle import default_bundle_root
from .corpus import load_corpus, verify_provenance
from .engines import compile_rule
from .errors import DetectionPlatformError
from .exporters import write_report_bundle
from .manifest import load_manifests, public_manifest
from .replay import run_replay
from .serialization import pretty_json


DEFAULT_AS_OF = date(2026, 7, 13)


def _date(value: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected ISO date YYYY-MM-DD") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="detection-platform",
        description="Versioned rule validation and deterministic historical replay",
    )
    parser.add_argument("--bundle", type=Path, default=default_bundle_root())
    subparsers = parser.add_subparsers(dest="subcommand", required=True)
    subparsers.add_parser(
        "validate", help="validate corpus, manifests, and rule syntax"
    )
    subparsers.add_parser("rules", help="list versioned rule metadata")

    verify = subparsers.add_parser(
        "verify-dataset", help="verify vendored integration provenance"
    )
    verify.add_argument("--upstream", type=Path)

    replay = subparsers.add_parser(
        "replay", help="run historical replay and lifecycle policy"
    )
    replay.add_argument("--as-of", type=_date, default=DEFAULT_AS_OF)
    replay.add_argument("--output-dir", type=Path)
    replay.add_argument("--full", action="store_true")

    server = subparsers.add_parser("serve", help="serve local API and dashboard")
    server.add_argument("--host", default="127.0.0.1")
    server.add_argument("--port", type=int, default=8080)
    return parser


def _execute(args: argparse.Namespace) -> int:
    bundle = args.bundle.resolve()
    if args.subcommand == "serve":
        if not 1 <= args.port <= 65535:
            raise ValueError("port must be between 1 and 65535")
        serve(args.host, args.port, bundle)
        return 0
    if args.subcommand == "verify-dataset":
        print(pretty_json(verify_provenance(bundle, args.upstream)), end="")
        return 0
    manifests = load_manifests(bundle)
    if args.subcommand == "rules":
        print(
            pretty_json({"rules": [public_manifest(item) for item in manifests]}),
            end="",
        )
        return 0
    if args.subcommand == "validate":
        cases, datasets = load_corpus(bundle)
        compiled = [compile_rule(item) for item in manifests]
        print(
            pretty_json(
                {
                    "valid": True,
                    "rules": len(compiled),
                    "cases": len(cases),
                    "datasets": len(datasets),
                    "engines": sorted({item.engine.value for item in manifests}),
                    "provenance": verify_provenance(bundle),
                }
            ),
            end="",
        )
        return 0
    report = run_replay(bundle, args.as_of)
    files = write_report_bundle(report, args.output_dir) if args.output_dir else {}
    if args.full:
        print(pretty_json(report), end="")
    else:
        print(
            pretty_json(
                {
                    "functional_sha256": report["functional_sha256"],
                    "summary": report["summary"],
                    "diagnostics": report["diagnostics"],
                    "measurement": report["measurement"],
                    "artifacts": files,
                    "audit_valid": verify_audit_chain(report["audit"]),
                    "deployment_effect": "none",
                }
            ),
            end="",
        )
    return 0 if report["summary"]["all_expected_decisions_met"] else 3


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return _execute(args)
    except (DetectionPlatformError, ValueError) as exc:
        print(
            json.dumps(
                {"error": type(exc).__name__, "detail": str(exc)}, sort_keys=True
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
