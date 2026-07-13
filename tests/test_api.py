from __future__ import annotations

import json
import threading
import unittest
import urllib.error
import urllib.request
from contextlib import contextmanager
from typing import Any, Dict, Iterator, Tuple

from detection_platform.api import create_server

from .helpers import BUNDLE


@contextmanager
def running_server() -> Iterator[Tuple[str, Any]]:
    server = create_server("127.0.0.1", 0, BUNDLE)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}", server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def read_json(url: str) -> Tuple[int, Dict[str, Any], Any]:
    with urllib.request.urlopen(url, timeout=5) as response:
        return response.status, json.load(response), response.headers


class ApiTests(unittest.TestCase):
    def test_health_rules_datasets_and_dashboard(self) -> None:
        with running_server() as (base, _):
            status, health, headers = read_json(base + "/api/v1/health")
            self.assertEqual(200, status)
            self.assertEqual("simulation-only", health["deployment_mode"])
            self.assertEqual("nosniff", headers["X-Content-Type-Options"])
            _, rules, _ = read_json(base + "/api/v1/rules")
            self.assertEqual(7, len(rules["rules"]))
            self.assertFalse(rules["rules"][0]["manifest_path"].startswith("/"))
            self.assertFalse(rules["rules"][0]["source_path"].startswith("/"))
            _, datasets, _ = read_json(base + "/api/v1/datasets")
            self.assertEqual(4, len(datasets["datasets"]))
            with urllib.request.urlopen(base + "/", timeout=5) as response:
                html = response.read().decode("utf-8")
                self.assertIn("Detection Engineering Control Plane", html)
                self.assertIn(
                    "default-src 'self'", response.headers["Content-Security-Policy"]
                )

    def test_replay_endpoint_runs_measured_policy(self) -> None:
        with running_server() as (base, _):
            request = urllib.request.Request(
                base + "/api/v1/replay",
                data=json.dumps({"as_of": "2026-07-13"}).encode("utf-8"),
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                report = json.load(response)
            self.assertTrue(report["summary"]["all_expected_decisions_met"])
            self.assertEqual(64, len(report["functional_sha256"]))

    def test_replay_endpoint_rejects_extra_fields(self) -> None:
        with running_server() as (base, _):
            request = urllib.request.Request(
                base + "/api/v1/replay",
                data=json.dumps(
                    {"as_of": "2026-07-13", "rule_text": "not accepted"}
                ).encode("utf-8"),
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            with self.assertRaises(urllib.error.HTTPError) as captured:
                urllib.request.urlopen(request, timeout=5)
            self.assertEqual(400, captured.exception.code)

    def test_replay_endpoint_rejects_duplicate_json_keys(self) -> None:
        with running_server() as (base, _):
            request = urllib.request.Request(
                base + "/api/v1/replay",
                data=b'{"as_of":"2026-07-13","as_of":"2027-01-01"}',
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            with self.assertRaises(urllib.error.HTTPError) as captured:
                urllib.request.urlopen(request, timeout=5)
            self.assertEqual(400, captured.exception.code)


if __name__ == "__main__":
    unittest.main()
