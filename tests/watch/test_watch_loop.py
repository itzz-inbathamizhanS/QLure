import json

from qlure.watch.egress import watch

LISTENER = (
    "   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1"  # noqa: E501
)
# Decoy (port 8080, hex 1F90) connected out to 203.0.113.9:4444.
OUTBOUND = (
    "   1: 0100A8C0:9C40 097100CB:115C 01 00000000:00000000 00:00000000 00000000     0        0 2"  # noqa: E501
)


def test_watch_reports_each_outbound_connection_once(tmp_path):
    (tmp_path / "net").mkdir()
    (tmp_path / "net" / "tcp").write_text(
        "  sl header\n" + LISTENER + "\n" + OUTBOUND + "\n", encoding="utf-8"
    )
    out = tmp_path / "logs" / "egress.jsonl"
    polls = []
    written = watch(out, tmp_path / "net", interval=0, iterations=3, sleep=polls.append)
    assert written == 1  # the same connection on three polls is one alert
    assert len(polls) == 2
    [line] = out.read_text().splitlines()
    alert = json.loads(line)
    assert alert["severity"] == "high"
    assert "ts" in alert


def test_watch_writes_nothing_when_the_decoy_is_quiet(tmp_path):
    (tmp_path / "tcp").write_text("  sl header\n" + LISTENER + "\n", encoding="utf-8")
    out = tmp_path / "egress.jsonl"
    assert watch(out, tmp_path, iterations=2, sleep=lambda _: None) == 0
    assert not out.exists()
