"""Detection-as-code validation, replay, and promotion platform."""

__version__ = "0.1.0"

from .bundle import default_bundle_root
from .replay import run_replay

__all__ = ["default_bundle_root", "run_replay"]
