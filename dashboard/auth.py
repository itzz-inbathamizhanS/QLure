"""One shared admin password and a signed, expiring session cookie."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import time

COOKIE = "qlure_admin"
LIFETIME = 8 * 3600


class Auth:
    def __init__(self) -> None:
        chosen = os.environ.get("QLURE_DASHBOARD_PASSWORD")
        self.password = chosen or secrets.token_urlsafe(12)
        self.generated = not chosen
        self.secret = (os.environ.get("QLURE_DASHBOARD_SECRET") or secrets.token_hex(32)).encode()

    def check_password(self, attempt: str) -> bool:
        return hmac.compare_digest(attempt.encode(), self.password.encode())

    def _sign(self, payload: str) -> str:
        return hmac.new(self.secret, payload.encode(), hashlib.sha256).hexdigest()

    def issue(self) -> str:
        payload = f"{int(time.time()) + LIFETIME}.{secrets.token_hex(8)}"
        return base64.urlsafe_b64encode(f"{payload}.{self._sign(payload)}".encode()).decode()

    def valid(self, cookie: str | None) -> bool:
        if not cookie:
            return False
        try:
            payload, signature = base64.urlsafe_b64decode(cookie.encode()).decode().rsplit(".", 1)
            expires = int(payload.split(".")[0])
        except (ValueError, UnicodeDecodeError):
            return False
        return hmac.compare_digest(signature, self._sign(payload)) and expires > time.time()
