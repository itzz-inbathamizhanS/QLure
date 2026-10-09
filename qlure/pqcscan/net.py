"""Connections pinned to already-validated addresses (see security/target_validator.py)."""

import socket

from qlure.pqcscan.errors import ScannerErrorType, ScannerException


def connect_pinned(ips, port: int, timeout: float) -> socket.socket:
    """Open a TCP connection to the first reachable address in `ips`. Never resolves a name."""
    last = None
    for ip in ips[:4]:
        try:
            return socket.create_connection((ip, port), timeout=timeout)
        except OSError as e:
            last = e
    if isinstance(last, (socket.timeout, TimeoutError)):
        raise ScannerException(
            ScannerErrorType.CONNECTION_TIMEOUT, f"Connection to port {port} timed out"
        )
    raise ScannerException(
        ScannerErrorType.TARGET_UNREACHABLE, f"Could not connect to port {port}: {last}"
    )
