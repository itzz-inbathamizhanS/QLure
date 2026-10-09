"""SSH key-exchange fingerprint: real client handshakes, and through the live relay."""

import asyncio
import socket
from pathlib import Path

import asyncssh
import pytest

from decoys import honeytokens
from decoys.ssh import server as ssh_server
from qlure.pqc.kex import KexSniffer, kex_fingerprint, pqc_capable

FIXTURES = Path(__file__).parent / "fixtures"
VISITOR = b"PROXY TCP4 198.51.100.8 10.0.0.1 40404 2222\r\n"


def sniff(data: bytes, chunk: int | None = None) -> KexSniffer:
    sniffer = KexSniffer()
    step = chunk or len(data)
    for i in range(0, len(data), step):
        sniffer.feed(data[i : i + step])
    return sniffer


def test_recent_openssh_offers_quantum_safe_exchange():
    # First bytes recorded from a real OpenSSH 9.6 client.
    s = sniff((FIXTURES / "openssh_9_6.bin").read_bytes())
    assert s.client_version.startswith("SSH-2.0-OpenSSH_9.6")
    assert "sntrup761x25519-sha512@openssh.com" in s.kex_offered
    assert pqc_capable(s.kex_offered) is True


def test_paramiko_does_not():
    # First bytes recorded from a real Paramiko 5.0 client.
    s = sniff((FIXTURES / "paramiko_5_0.bin").read_bytes())
    assert s.client_version.startswith("SSH-2.0-paramiko")
    assert s.kex_offered and pqc_capable(s.kex_offered) is False


def test_split_packets_and_junk():
    data = (FIXTURES / "openssh_9_6.bin").read_bytes()
    assert sniff(data, chunk=7).kex_offered == sniff(data).kex_offered
    junk = sniff(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    assert junk.done and junk.kex_offered == [] and junk.client_version == ""
    assert sniff(b"SSH-2.0-banner-only\r\n").kex_offered == []
    assert kex_fingerprint(["a", "b"]) != kex_fingerprint(["b", "a"])
    assert len(kex_fingerprint(["a"])) == 16


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_decoy_logs_the_offer_and_negotiates_hybrid_exchange(log_dir, read_events):
    async def connect(listen: int, kex: list[str], password: str):
        sock = socket.create_connection(("127.0.0.1", listen))
        sock.sendall(VISITOR)
        sock.setblocking(False)
        return await asyncssh.connect(
            "127.0.0.1",
            sock=sock,
            username="deploy",
            password=password,
            known_hosts=None,
            kex_algs=kex,
            client_version="paramiko_9.9" if kex == ["curve25519-sha256"] else "OpenSSH_10.0",
        )

    async def scenario():
        listen, backend = free_port(), free_port()
        task = asyncio.create_task(ssh_server.serve(listen, backend))
        for _ in range(50):
            try:
                _, w = await asyncio.open_connection("127.0.0.1", listen)
                w.close()
                break
            except OSError:
                await asyncio.sleep(0.05)
        try:
            password = honeytokens.get("ht-ssh-001")["value"]
            async with await connect(listen, ["mlkem768x25519-sha256"], password) as conn:
                await conn.run("whoami", check=False)
            async with await connect(listen, ["curve25519-sha256"], password) as conn:
                await conn.run("id", check=False)
        finally:
            task.cancel()

    try:
        asyncio.run(scenario())
    except asyncssh.KeyExchangeFailed:
        pytest.fail("the decoy did not offer mlkem768x25519-sha256")

    events = read_events("ssh")
    connects = [e for e in events if e.action.value == "connect"]
    assert [c.pqc_capable for c in connects] == [True, False]
    assert connects[0].kex_offered[0] == "mlkem768x25519-sha256"
    assert connects[0].kex_fp == kex_fingerprint(connects[0].kex_offered)
    assert connects[0].client_fp and connects[0].client_fp != connects[1].client_fp
    for session in {e.session_id for e in events}:
        mine = [e for e in events if e.session_id == session]
        assert len({e.client_fp for e in mine}) == 1  # one fingerprint for the whole session
        assert min(mine, key=lambda e: e.ts).action.value == "connect"
    logins = [e for e in events if e.action.value == "login_attempt"]
    assert all(e.pqc_capable is not None and e.kex_offered is None for e in logins)
    assert all(e.pqc_capable is None for e in events if e.action.value == "command")
