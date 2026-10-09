"""Operator settings: validated, audited and reversible.

Only settings that cannot make a decoy dangerous exist. There is no setting for outbound
network access, command execution, executable uploads or host folder mounts, and a request
that names one is refused and logged. Every accepted or refused change goes to config_audit.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import os
import re
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from qlure.store.chain import GENESIS, config_hash

RULES_FILE = Path(__file__).resolve().parent / "rules" / "rules.yaml"

DASHBOARD_PORT = 9000
# Ports a decoy may use. Nothing below 1024, and never the dashboard's own port.
APPROVED_PORTS: dict[str, list[int]] = {
    "web": [8080, 8088, 8888],
    "api": [8081, 8082],
    "ssh": [2222, 2200],
    "ftp": [2121],
    "mysql": [3306, 3307],
    "redis": [6379, 6380],
}
# Names that must never become settings.
FORBIDDEN_KEYS = {
    "outbound_network": "no setting exists for outbound network access",
    "outbound": "no setting exists for outbound network access",
    "network_access": "no setting exists for network access",
    "command_execution": "no setting exists for real command execution",
    "exec": "no setting exists for real command execution",
    "executable_uploads": "no setting exists for executable uploads",
    "host_mounts": "no setting exists for host folder mounts",
    "volumes": "no setting exists for host folder mounts",
}
# Fake content must not look like a real secret.
SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{36}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\b[\w.-]+\.(corp|intranet|local)\b"),
]


class Decoy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True
    port: int


class Content(BaseModel):
    model_config = ConfigDict(extra="forbid")
    company_name: str = Field(default="Veltrix Logistics", min_length=1, max_length=60)
    ftp_banner: str = Field(
        default="220 ProFTPD 1.3.8 Server (Veltrix Files)", min_length=4, max_length=120
    )

    @field_validator("company_name", "ftp_banner")
    @classmethod
    def _no_real_secrets(cls, value: str) -> str:
        for pattern in SECRET_PATTERNS:
            if pattern.search(value):
                raise ValueError("looks like a real secret or internal hostname")
        if "\r" in value or "\n" in value:
            raise ValueError("must be a single line")
        return value


class RuleTuning(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suspicious: int = Field(default=30, ge=1, le=99)
    noteworthy: int = Field(default=60, ge=2, le=100)
    weights: dict[str, int] = Field(default_factory=dict)
    thresholds: dict[str, dict[str, int]] = Field(default_factory=dict)


class Allowlist(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ips: list[str] = Field(default_factory=list, max_length=50)
    user_agents: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("ips")
    @classmethod
    def _valid_ips(cls, values: list[str]) -> list[str]:
        return [str(ipaddress.ip_address(v)) for v in values]


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    judge_mode: bool = False
    decoys: dict[Literal["web", "api", "ssh", "ftp", "mysql", "redis"], Decoy]
    content: Content = Field(default_factory=Content)
    rules: RuleTuning = Field(default_factory=RuleTuning)
    allowlist: Allowlist = Field(default_factory=Allowlist)
    retention_days: int = Field(default=30, ge=1, le=365)

    @field_validator("decoys")
    @classmethod
    def _approved_ports(cls, decoys: dict[str, Decoy]) -> dict[str, Decoy]:
        for name, decoy in decoys.items():
            if decoy.port < 1024 or decoy.port == DASHBOARD_PORT:
                raise ValueError(f"{name}: port {decoy.port} is not allowed")
            if decoy.port not in APPROVED_PORTS[name]:
                raise ValueError(f"{name}: port {decoy.port} is not on the approved list")
        return decoys


def defaults() -> dict[str, Any]:
    return Settings(
        decoys={name: Decoy(port=ports[0]) for name, ports in APPROVED_PORTS.items()}
    ).model_dump(mode="json")


def settings_path() -> Path:
    return Path(os.environ.get("QLURE_SETTINGS", "data/settings.json"))


def content_path() -> Path:
    """Where the decoys' read-only copy of the fake-content settings is written."""
    return Path(os.environ.get("QLURE_CONTENT", str(settings_path().with_name("content.json"))))


def load_settings(path: Path | None = None) -> dict[str, Any]:
    """The saved settings merged over the defaults. Missing or unreadable file means defaults."""
    merged = defaults()
    try:
        saved = json.loads((path or settings_path()).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return merged
    return _merge(merged, saved)


def _merge(base: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


def _get(data: dict[str, Any], path: str) -> Any:
    node: Any = data
    for part in path.split("."):
        node = node.get(part) if isinstance(node, dict) else None
    return node


def _set(data: dict[str, Any], path: str, value: Any) -> bool:
    """Set a dotted path. False (and no change) if it would go below a plain value."""
    parts = path.split(".")
    node = data
    for part in parts[:-1]:
        node = node.setdefault(part, {})
        if not isinstance(node, dict):
            return False
    node[parts[-1]] = value
    return True


def _forbidden(path: str) -> str | None:
    for part in path.split("."):
        if part in FORBIDDEN_KEYS:
            return FORBIDDEN_KEYS[part]
    return None


def audit(
    conn: sqlite3.Connection, who: str, key: str, old: Any, new: Any, outcome: str, reason: str
) -> None:
    last = conn.execute("SELECT hash FROM config_audit ORDER BY audit_id DESC LIMIT 1").fetchone()
    prev = last["hash"] if last and last["hash"] else GENESIS
    row = {
        "ts": datetime.now(UTC).isoformat(),
        "who": who,
        "key": key,
        "old_value": json.dumps(old),
        "new_value": json.dumps(new),
        "outcome": outcome,
        "reason": reason,
    }
    conn.execute(
        "INSERT INTO config_audit"
        " (ts, who, key, old_value, new_value, outcome, reason, prev_hash, hash)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        (
            row["ts"],
            row["who"],
            row["key"],
            row["old_value"],
            row["new_value"],
            row["outcome"],
            row["reason"],
            prev,
            config_hash(prev, row),
        ),
    )
    conn.commit()


def apply_change(
    conn: sqlite3.Connection, who: str, changes: dict[str, Any], path: Path | None = None
) -> tuple[bool, str]:
    """Apply dotted-path changes, e.g. {"decoys.ssh.port": 2200}. All or nothing."""
    target = path or settings_path()
    current = load_settings(target)
    candidate = copy.deepcopy(current)
    allowed_in_judge_mode = {"judge_mode"}

    for key, value in changes.items():
        reason = _forbidden(key)
        if reason is None and current.get("judge_mode") and key not in allowed_in_judge_mode:
            reason = "judge mode is on: settings are read-only"
        if reason is None and not _set(candidate, key, value):
            reason = "not a setting: the path goes below a plain value"
        if reason is not None:
            audit(conn, who, key, _get(current, key), value, "refused", reason)
            return False, f"{key}: {reason}"

    try:
        valid = Settings.model_validate(candidate).model_dump(mode="json")
    except ValidationError as exc:
        error = exc.errors()[0]
        reason = f"{'.'.join(str(p) for p in error['loc'])}: {error['msg']}"
        for key, value in changes.items():
            audit(conn, who, key, _get(current, key), value, "refused", reason)
        return False, reason

    rules_error = _check_rule_tuning(valid)
    if rules_error:
        for key, value in changes.items():
            audit(conn, who, key, _get(current, key), value, "refused", rules_error)
        return False, rules_error

    content_target = content_path() if path is None else target.with_name("content.json")
    old_settings = _read_bytes(target)
    old_content = _read_bytes(content_target)
    try:
        # Content first, then settings, then the audit rows. Any failure puts both files back.
        _write_atomic(content_target, json.dumps(valid["content"], indent=2))
        _write_atomic(target, json.dumps(valid, indent=2))
        for key in changes:
            audit(conn, who, key, _get(current, key), _get(valid, key), "applied", "")
    except Exception as exc:
        _restore(target, old_settings)
        _restore(content_target, old_content)
        conn.rollback()
        return False, f"change not applied, could not record it: {exc}"
    from qlure.correlate.rules import load_config  # local: avoid a circular import

    load_config.cache_clear()
    return True, "saved"


def _read_bytes(path: Path) -> bytes | None:
    try:
        return path.read_bytes()
    except OSError:
        return None


def _restore(path: Path, data: bytes | None) -> None:
    try:
        if data is None:
            path.unlink(missing_ok=True)
        else:
            path.write_bytes(data)
    except OSError:
        pass


def _write_atomic(path: Path, text: str) -> None:
    """The decoys read only the small content file, never the full settings or the database."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


# Listed in rules.yaml for the explanation text, but no rule code reads them.
UNREAD_THRESHOLDS = {
    ("R4", "pairs"),
    ("R5", "matches"),
    ("R6", "matches"),
    ("R7", "uses"),
    ("R9", "reads"),
}


def _check_rule_tuning(valid: dict[str, Any]) -> str | None:
    rules = yaml.safe_load(RULES_FILE.read_text(encoding="utf-8"))["rules"]
    tuning = valid["rules"]
    if tuning["suspicious"] >= tuning["noteworthy"]:
        return "rules: the suspicious threshold must be below the noteworthy threshold"
    for rule_id, weight in tuning["weights"].items():
        if rule_id not in rules:
            return f"rules.weights.{rule_id}: unknown rule"
        if not 0 <= weight <= 100:
            return f"rules.weights.{rule_id}: must be between 0 and 100"
    for rule_id, values in tuning["thresholds"].items():
        if rule_id not in rules:
            return f"rules.thresholds.{rule_id}: unknown rule"
        for name, number in values.items():
            if name not in rules[rule_id]["threshold"]:
                return f"rules.thresholds.{rule_id}.{name}: unknown threshold"
            if (rule_id, name) in UNREAD_THRESHOLDS:
                return f"rules.thresholds.{rule_id}.{name}: no rule reads this threshold"
            if not 1 <= number <= 1000:
                return f"rules.thresholds.{rule_id}.{name}: must be between 1 and 1000"
    return None


def rollback(conn: sqlite3.Connection, who: str, audit_id: int) -> tuple[bool, str]:
    row = conn.execute(
        "SELECT key, old_value, outcome FROM config_audit WHERE audit_id=?", (audit_id,)
    ).fetchone()
    if row is None or row["outcome"] != "applied":
        return False, "only an applied change can be rolled back"
    if row["key"].startswith("data."):
        return False, "clearing data is recorded here but cannot be rolled back"
    return apply_change(conn, who, {row["key"]: json.loads(row["old_value"])})


def schema() -> dict[str, Any]:
    out = Settings.model_json_schema()
    out["title"] = "Q-Lure settings"
    return out
