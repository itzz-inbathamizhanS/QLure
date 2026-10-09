import asyncio
import socket

import asyncssh

from decoys import honeytokens
from decoys.ssh import server as ssh_server

VISITOR = b"PROXY TCP4 198.51.100.7 10.0.0.1 40404 2222\r\n"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


async def _wait_for_port(port: int) -> None:
    for _ in range(50):
        try:
            _, writer = await asyncio.open_connection("127.0.0.1", port)
        except OSError:
            await asyncio.sleep(0.05)
            continue
        writer.close()
        return
    raise RuntimeError(f"port {port} never opened")


async def _connect(listen_port: int, username: str, password: str):
    """Connect through the relay as the gateway would: PROXY line first, then SSH."""
    sock = socket.create_connection(("127.0.0.1", listen_port))
    sock.sendall(VISITOR)
    sock.setblocking(False)
    return await asyncssh.connect(
        "127.0.0.1", sock=sock, username=username, password=password, known_hosts=None
    )


def test_ssh_login_commands_and_honeytoken_chain(log_dir, read_events):
    async def scenario():
        listen, backend = free_port(), free_port()
        task = asyncio.create_task(ssh_server.serve(listen, backend))
        await _wait_for_port(listen)
        try:
            # Wrong password is refused and logged.
            try:
                await _connect(listen, "deploy", "wrong-guess")
                refused = False
            except asyncssh.PermissionDenied:
                refused = True
            assert refused

            # The planted password gets in.
            password = honeytokens.get("ht-ssh-001")["value"]
            async with await _connect(listen, "deploy", password) as conn:
                whoami = (await conn.run("whoami", check=False)).stdout
                history = (await conn.run("cat ~/.bash_history", check=False)).stdout
                unknown = (await conn.run("nosuchtool", check=False)).stdout
            return whoami, history, unknown
        finally:
            task.cancel()

    whoami, history, unknown = asyncio.run(scenario())
    assert whoami == "deploy\n"
    assert honeytokens.get("ht-api-001")["value"] in history
    assert "command not found" in unknown

    events = read_events("ssh")
    actions = [e.action for e in events]
    assert actions[0] == "connect"
    assert all(e.src_ip == "198.51.100.7" for e in events)
    attempts = [e for e in events if e.action == "login_attempt"]
    assert [a.credential.password for a in attempts][0] == "wrong-guess"
    assert attempts[0].honeytoken_id is None
    assert attempts[-1].honeytoken_id == "ht-ssh-001"
    assert "login_success" in actions and "honeytoken_use" in actions
    commands = [e.request["command"] for e in events if e.action == "command"]
    assert commands == ["whoami", "cat ~/.bash_history", "nosuchtool"]
