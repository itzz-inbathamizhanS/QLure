"""The tight-burst session merge: fixes fragmentation against a changing client_fp,
without merging two unrelated visitors behind one address."""

from datetime import UTC, datetime

from helpers import run, web

from qlure.correlate.sessions import BURST_GAP, MIN_BURST_EVENTS, build_sessions
from qlure.events import Action, Event, Service

START = datetime(2026, 1, 1, tzinfo=UTC)


def _event(ip: str, idx: int, offset) -> Event:
    return Event(
        event_id=f"ev-{idx:04d}",
        ts=START + offset,
        service=Service.WEB,
        src_ip=ip,
        src_port=1234,
        client_fp=f"fp-{idx}",  # a different fingerprint on every event, like Nikto's
        session_id=f"sid-{idx}",  # and no shared decoy session id either
        action=Action.HTTP_REQUEST,
        request={"method": "GET", "path": "/x"},
    )


def test_a_long_tight_burst_with_a_changing_fingerprint_becomes_one_session():
    events = [_event("198.51.100.50", i, i * (BURST_GAP / 2)) for i in range(MIN_BURST_EVENTS + 20)]
    sessions = build_sessions(events)
    assert len(sessions) == 1
    assert len(sessions[0].events) == len(events)


def test_a_short_run_does_not_merge_even_with_a_tight_gap():
    events = [_event("198.51.100.51", i, i * (BURST_GAP / 2)) for i in range(MIN_BURST_EVENTS - 1)]
    sessions = build_sessions(events)
    assert len(sessions) == len(events)  # every fingerprint differs and the run is too short


def test_a_gap_over_the_limit_breaks_the_burst():
    first = [_event("198.51.100.52", i, i * (BURST_GAP / 2)) for i in range(MIN_BURST_EVENTS + 2)]
    late = first[-1].ts - START + BURST_GAP * 3
    second = [
        _event("198.51.100.52", 100 + i, late + i * (BURST_GAP / 2))
        for i in range(MIN_BURST_EVENTS + 2)
    ]
    sessions = build_sessions(first + second)
    assert len(sessions) == 2
    assert {len(s.events) for s in sessions} == {len(first)}


def test_two_visitors_behind_one_address_never_merge(read_events):
    # The existing guarantee this change must not touch, driven through the real decoy.
    web("198.51.100.210", agent="Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0").get("/login")
    web("198.51.100.210", agent="Mozilla/5.0 (Macintosh) Safari/17").get("/login")
    result = run(read_events)
    assert len(result.sessions) == 2
    assert len(result.actors) == 2


def test_a_real_nikto_style_scan_scores_as_one_noteworthy_session(read_events):
    client = web("198.51.100.211", agent="Nikto/2.1.5")
    for i in range(30):
        client.headers["user-agent"] = f"Mozilla/5.00 (Nikto/2.1.5) (Test:{i:06d})"
        client.get("/wp-login.php" if i % 5 else "/phpmyadmin/")
    result = run(read_events)
    finding = next(f for f in result.findings if f.session.src_ip == "198.51.100.211")
    assert len(finding.session.events) == 30
    assert finding.score > 0 and "R6" in {h.rule_id for h in finding.hits}
