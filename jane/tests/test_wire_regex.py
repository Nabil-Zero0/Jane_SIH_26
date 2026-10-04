"""
Tests for Step 7: Regex false positive prevention for Wire handles.
Verifies:
1. "Wire transfer", "wire transfers", "wire payment", etc. do not yield handles.
2. Legitimate Wire handles (e.g. "wire: @realuser", "wire: shadow_trader") are extracted.
"""

import pytest
from jane.backend.regex_patterns import _WIRE_HANDLE_RE, _extract_wire_handle


def test_wire_handle_regex_negative_cases():
    negative_samples = [
        "Payment accepted via Wire transfer.",
        "Wire transfers are fast and anonymous.",
        "Submit wire payment immediately.",
        "We accept wire payments and Bitcoin.",
        "Wire service available 24/7.",
        "Follow wire instructions carefully.",
        "Beware of wire fraud and impersonators.",
        "Wire deposit required before escrow.",
        "Contact wire: transfer.",
        "wire: transfer",
        "wire-transfer",
        "Wire money to bank account.",
        "Wire funds directly.",
    ]
    for sample in negative_samples:
        matches = list(_WIRE_HANDLE_RE.finditer(sample))
        assert len(matches) == 0, f"Expected no match for {sample!r}, got {[m.group(0) for m in matches]}"
        handles = _extract_wire_handle(sample)
        assert len(handles) == 0, f"Expected no handles extracted from {sample!r}, got {handles}"


def test_wire_handle_regex_positive_cases():
    positive_samples = [
        ("Contact wire: @realuser for keys.", "realuser"),
        ("My handle is wire: shadow_trader", "shadow_trader"),
        ("Ping me on wire.com: bob_smith", "bob_smith"),
        ("Support via Wire: vendor99", "vendor99"),
        ("Reach out at wire: @alpha_trader_01", "alpha_trader_01"),
    ]
    for sample, expected in positive_samples:
        handles = _extract_wire_handle(sample)
        assert expected in handles, f"Expected {expected!r} in extracted handles from {sample!r}, got {handles}"
