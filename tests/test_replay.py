"""
Test Suite: Replay Protection Window and Sequence Tracking.
"""
import pytest
from common.replay_window import (
    ReplayProtectionWindow,
    DuplicatePacketError,
    StalePacketError,
)


def test_monotonic_packets_accepted():
    window = ReplayProtectionWindow(window_size=64)
    session = 100

    for c in range(1, 10):
        ok, reason = window.check(session, c)
        assert ok, f"Counter {c} check failed: {reason}"
        window.commit(session, c)

    assert window.max_counter == 9


def test_duplicate_counter_rejected():
    window = ReplayProtectionWindow(window_size=64)
    session = 100

    window.commit(session, 5)

    # Pre-check fails
    ok, reason = window.check(session, 5)
    assert not ok
    assert "Duplicate" in reason

    # Direct commit raises exception
    with pytest.raises(DuplicatePacketError):
        window.commit(session, 5)


def test_out_of_order_within_window_accepted():
    window = ReplayProtectionWindow(window_size=64)
    session = 100

    # Receive packets 1, 3, 2
    window.commit(session, 1)
    window.commit(session, 3)

    # 2 is in-window out-of-order
    ok, reason = window.check(session, 2)
    assert ok
    window.commit(session, 2)

    # Now 2 cannot be re-committed
    ok, reason = window.check(session, 2)
    assert not ok


def test_stale_counter_outside_window_rejected():
    window = ReplayProtectionWindow(window_size=64)
    session = 100

    # Advance to counter 100
    window.commit(session, 100)

    # Counter 100 - 65 = 35 is stale (> 64 window)
    ok, reason = window.check(session, 35)
    assert not ok
    assert "Stale" in reason

    with pytest.raises(StalePacketError):
        window.commit(session, 35)

