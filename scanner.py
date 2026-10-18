#!/usr/bin/env python3
"""Entry point kept for ``python scanner.py --url ...`` usage; see moodle_scanner.cli."""

from moodle_scanner.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
