#!/usr/bin/env python3
"""pytest entry point for test_stream.py's checks.

test_stream.py predates pytest-style naming (it's a standalone `main()` you
can also just run directly - see CLAUDE.md) and pytest doesn't collect a bare
main(), so `python -m pytest -q` silently collected zero tests here. This
just gives pytest a test_*-prefixed hook onto the same checks.
"""
import test_stream


def test_stream_offline_checks():
    test_stream.main()
