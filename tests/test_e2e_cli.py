from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

from .helpers import BUNDLE, ROOT


class CliEndToEndTests(unittest.TestCase):
    def _run(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(ROOT / "src")
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "detection_platform",
                "--bundle",
                str(BUNDLE),
                *arguments,
            ],
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            check=False,
        )

    def test_validate_and_replay_export(self) -> None:
        validation = self._run("validate")
        self.assertEqual(0, validation.returncode, validation.stderr)
        self.assertTrue(json.loads(validation.stdout)["valid"])
        with tempfile.TemporaryDirectory() as directory:
            replay = self._run(
                "replay", "--as-of", "2026-07-13", "--output-dir", directory
            )
            self.assertEqual(0, replay.returncode, replay.stderr)
            payload = json.loads(replay.stdout)
            self.assertEqual(4, len(payload["artifacts"]))
            self.assertEqual("none", payload["deployment_effect"])

    def test_invalid_bundle_has_structured_failure(self) -> None:
        result = self._run("--bundle", str(ROOT / "missing"), "validate")
        self.assertNotEqual(0, result.returncode)


if __name__ == "__main__":
    unittest.main()
