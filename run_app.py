#!/usr/bin/env python3
"""Launcher for the PLDM Parser GUI.

Double-click this file or run:
    python run_app.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow running from a clone without `pip install`.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from pldm_parser.gui import main

if __name__ == "__main__":
    raise SystemExit(main())
