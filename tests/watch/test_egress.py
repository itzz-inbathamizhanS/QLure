from qlure.watch.egress import alerts_for, find_outbound, parse_proc_net, scan

HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"  # noqa: E501

# Decoy listens on 0.0.0.0:2222 (hex 08AE) and has an attacker connected to it (inbound).
INBOUND = (
    "   0: 00000000:08AE 0A00A8C0:D2F0 01 00000000:00000000 00:00000000 00000000     0        0 1"  # noqa: E501
)
LISTENER = (
    "   1: 00000000:08AE 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2"  # noqa: E501
)
# The decoy itself connected out to 203.0.113.9:4444 from ephemeral port 40000 (hex 9C40).
OUTBOUND_C2 = (
    "   2: 0100A8C0:9C40 097100CB:115C 01 00000000:00000000 00:00000000 00000000     0        0 3"  # noqa: E501
)
# Loopback chatter should never alert.
LOOPBACK = (
    "   3: 0100007F:9C41 0100007F:1F90 01 00000000:00000000 00:00000000 00000000     0        0 4"  # noqa: E501
)


def _proc(*lines):
    return "\n".join([HEADER, *lines]) + "\n"


def test_decodes_addresses_and_ports():
    [conn] = [c for c in parse_proc_net(_proc(OUTBOUND_C2))]
    assert conn.local_ip == "192.168.0.1"
    assert conn.local_port == 40000
    assert conn.remote_ip == "203.0.113.9"
    assert conn.remote_port == 4444


def test_inbound_connections_on_a_listener_are_not_outbound():
    sockets = parse_proc_net(_proc(LISTENER, INBOUND))
    assert find_outbound(sockets) == []


def test_outbound_c2_connection_is_high_severity_with_ttp():
    sockets = parse_proc_net(_proc(LISTENER, INBOUND, OUTBOUND_C2, LOOPBACK))
    [alert] = alerts_for(find_outbound(sockets))
    assert alert["severity"] == "high"
    assert alert["remote"] == "203.0.113.9:4444"
    assert alert["mitre_attack_ttps"] == ["T1571"]


def test_other_outbound_connection_is_medium_severity(tmp_path):
    line = "   4: 0100A8C0:9C50 0100A8C0:0050 01 00000000:00000000 00:00000000 00000000     0        0 5"  # noqa: E501
    # 192.168.0.1 is private but not loopback, so it counts as outbound.
    (tmp_path / "tcp").write_text(_proc(line), encoding="utf-8")
    [alert] = scan(tmp_path)
    assert alert["severity"] == "medium"
    assert alert["mitre_attack_ttps"] == ["T1041"]


def test_scan_reads_tcp_and_tcp6_and_ignores_missing_files(tmp_path):
    (tmp_path / "tcp").write_text(_proc(LISTENER, INBOUND, OUTBOUND_C2), encoding="utf-8")
    assert len(scan(tmp_path)) == 1
    assert scan(tmp_path / "missing") == []
