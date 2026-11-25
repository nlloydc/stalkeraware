#!/usr/bin/env python3
"""stalkeraware.py - one entry point for every pass. Run with `python3 -I stalkeraware.py <command> ...`.

-I keeps Python from importing anything from the current folder (which may hold untrusted evidence). It also
stops Python adding this script's own folder to the import path, so the line below adds it explicitly: only
this repository's `sawtools` package is imported from here.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

from sawtools.cli import main  # noqa: E402

if __name__ == "__main__":
    main()
