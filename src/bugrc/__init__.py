"""Backward-compatible import alias for the renamed RCPatch package.

New code should import :mod:`rcpatch`.  This shim keeps existing BugRC scripts
and experiment artifacts working during the project rename.
"""

from __future__ import annotations

import importlib
import sys

_rcpatch = importlib.import_module("rcpatch")
sys.modules[__name__] = _rcpatch
