from __future__ import annotations

import shutil
from pathlib import Path
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "src" / "detection_platform" / "bundle"


class BundleCopy:
    def __init__(self) -> None:
        self._temporary = TemporaryDirectory()
        self.path = Path(self._temporary.name) / "bundle"
        shutil.copytree(BUNDLE, self.path)

    def cleanup(self) -> None:
        self._temporary.cleanup()
