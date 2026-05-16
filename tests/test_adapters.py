"""Wire contracts for adapters: format detection, HAR/Burp/JSONL parsing.

Without these tests, a change to detect_input_format could silently route
a file to the wrong parser, producing empty or corrupted flows.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from apisniff.bundle import detect_input_format

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.mark.parametrize(
    "filename, expected_format",
    [
        ("minimal.har", "har"),
        ("minimal.burp.xml", "burp"),
        ("minimal.jsonl", "jsonl"),
        ("empty.har", "har"),
        ("redaction.jsonl", "jsonl"),
    ],
)
def test_detect_input_format(filename, expected_format):
    head = (FIXTURES_DIR / filename).read_text()[:1024]
    assert detect_input_format(head) == expected_format
