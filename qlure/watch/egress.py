"""Egress watchdog: a decoy should never open an outbound connection.

Reads the Linux socket tables (/proc/net/tcp and /proc/net/tcp6) from inside a decoy's network
namespace. Attacker connections arrive on a decoy's listening port, so they count as inbound.
A connection whose local port is not a listener was opened by the decoy itself, so it is outbound.

Ported from HybridDFIR's connection_scanner.py: the same command-and-control port list and the
same ATT&CK ids, but applied to decoy containers instead of a Windows host.
"""

from __future__ import annotations

import ipaddress
import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ESTABLISHED = "01"
SYN_SENT = "02"
LISTEN = "0A"
_OUTBOUND_STATES = {ESTABLISHED, SYN_SENT}

# Ports commonly used by command-and-control frameworks and reverse shells.
C2_PORTS = frozenset({1234, 1337, 4443, 4444, 6666, 6667, 8888, 9999, 12345, 31337, 50050, 54321})
C2_MITRE = "T1571"  # Non-Standard Port
OUTBOUND_MITRE = "T1041"  # Exfiltration Over C2 Channel


@dataclass(frozen=True)
class Socket:
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str


def _decode_ip(hex_ip: str) -> str:
    raw = bytes.fromhex(hex_ip)
    # /proc stores each 32-bit group in host (little-endian) byte order.
    groups = [raw[i : i + 4][::-1] for i in range(0, len(raw), 4)]
    return str(ipaddress.ip_address(b"".join(groups)))


def parse_proc_net(text: str) -> list[Socket]:
    sockets = []
    for line in text.splitlines()[1:]:  # first line is the header
        fields = line.split()
        if len(fields) < 4:
            continue
        local_hex, remote_hex, state = fields[1], fields[2], fields[3]
        local_ip, local_port = local_hex.split(":")
        remote_ip, remote_port = remote_hex.split(":")
        sockets.append(
            Socket(
                local_ip=_decode_ip(local_ip),
                local_port=int(local_port, 16),
                remote_ip=_decode_ip(remote_ip),
                remote_port=int(remote_port, 16),
                state=state,
            )
        )
    return sockets


def _is_internal(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return addr.is_loopback or addr.is_unspecified


def find_outbound(sockets: list[Socket]) -> list[Socket]:
    listening = {s.local_port for s in sockets if s.state == LISTEN}
    return [
        s
        for s in sockets
        if s.state in _OUTBOUND_STATES
        and s.local_port not in listening
        and not _is_internal(s.remote_ip)
    ]


def alerts_for(outbound: list[Socket]) -> list[dict[str, Any]]:
    alerts = []
    for s in outbound:
        c2 = s.remote_port in C2_PORTS
        alerts.append(
            {
                "event_type": "EGRESS_FROM_DECOY",
                "severity": "high" if c2 else "medium",
                "local": f"{s.local_ip}:{s.local_port}",
                "remote": f"{s.remote_ip}:{s.remote_port}",
                "state": s.state,
                "mitre_attack_ttps": [C2_MITRE] if c2 else [OUTBOUND_MITRE],
                "description": "Decoy opened an outbound connection"
                + (" on a command-and-control port" if c2 else ""),
            }
        )
    return alerts


def scan(proc_net: str | Path = "/proc/net") -> list[dict[str, Any]]:
    """Scan one network namespace. Pass a different root in tests or when the watchdog runs
    outside the decoy (for example, /proc/<pid>/net)."""
    root = Path(proc_net)
    sockets: list[Socket] = []
    for name in ("tcp", "tcp6"):
        path = root / name
        if path.is_file():
            sockets += parse_proc_net(path.read_text(encoding="utf-8", errors="replace"))
    return alerts_for(find_outbound(sockets))


def watch(
    out: Path,
    proc_net: str | Path = "/proc/net",
    interval: float = 5.0,
    iterations: int | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    """Poll the namespace and append each new alert to `out` as JSON Lines.

    A connection that stays open is reported once, not on every poll. Returns the number of
    alerts written. `iterations=None` runs until the process is stopped.
    """
    seen: set[tuple[str, str]] = set()
    written = 0
    polls = 0
    while iterations is None or polls < iterations:
        fresh = [a for a in scan(proc_net) if (a["local"], a["remote"]) not in seen]
        if fresh:
            out.parent.mkdir(parents=True, exist_ok=True)
            now = datetime.now(UTC).isoformat()
            with out.open("a", encoding="utf-8") as fh:
                for alert in fresh:
                    seen.add((alert["local"], alert["remote"]))
                    fh.write(json.dumps({"ts": now, **alert}) + "\n")
            written += len(fresh)
        polls += 1
        if iterations is None or polls < iterations:
            sleep(interval)
    return written
