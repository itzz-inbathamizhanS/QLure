"""The Q-Lure event schema: the one contract every decoy writes and every module reads.

Rule for changes: fields are only ever added, never renamed or removed.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Action(StrEnum):
    CONNECT = "connect"
    BANNER = "banner"
    HTTP_REQUEST = "http_request"
    LOGIN_ATTEMPT = "login_attempt"
    LOGIN_SUCCESS = "login_success"
    COMMAND = "command"
    FILE_READ = "file_read"
    API_CALL = "api_call"
    HONEYTOKEN_USE = "honeytoken_use"
    DISCONNECT = "disconnect"


class Service(StrEnum):
    WEB = "web"
    API = "api"
    SSH = "ssh"
    FTP = "ftp"
    MYSQL = "mysql"
    REDIS = "redis"
    DOCKER = "docker"


class Credential(BaseModel):
    """A username/password pair exactly as the visitor typed it."""

    model_config = ConfigDict(extra="forbid")

    username: str | None = None
    password: str | None = None


SSH_ONLY_FIELDS = ("kex_offered", "kex_fp", "pqc_capable")


class Event(BaseModel):
    """One thing a visitor did to one decoy."""

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(description="Unique id, assigned by emit().")
    ts: datetime = Field(description="UTC time the decoy saw the event, assigned by emit().")
    replay_ts: datetime | None = Field(
        default=None, description="Original timestamp when the event came from `qlure replay`."
    )
    service: Service
    src_ip: str = Field(description="Visitor IP address as seen by the decoy.")
    src_port: int | None = Field(default=None, ge=0, le=65535)
    client_fp: str | None = Field(
        default=None, description="Client fingerprint (e.g. hash of HTTP headers or SSH KEXINIT)."
    )
    session_id: str = Field(min_length=1, description="Decoy-level session (cookie, connection).")
    actor_id: str | None = Field(default=None, description="Filled in by the correlation engine.")
    action: Action
    request: dict[str, Any] | None = None
    response: dict[str, Any] | None = None
    credential: Credential | None = None
    honeytoken_id: str | None = None
    rule_hits: list[str] = Field(default_factory=list)
    prev_hash: str | None = Field(default=None, description="Hash chain link, set by the store.")
    hash: str | None = Field(default=None, description="SHA-256 of this event, set by the store.")
    kex_offered: list[str] | None = Field(default=None, description="SSH only: client KEX list.")
    kex_fp: str | None = Field(default=None, description="SSH only: short hash of kex_offered.")
    pqc_capable: bool | None = Field(
        default=None, description="SSH only: client offers a post-quantum KEX. Context only."
    )

    @field_validator("src_ip")
    @classmethod
    def _valid_ip(cls, value: str) -> str:
        return str(ipaddress.ip_address(value))

    @model_validator(mode="after")
    def _ssh_fields_only_on_ssh(self) -> Event:
        if self.service is not Service.SSH:
            used = [name for name in SSH_ONLY_FIELDS if getattr(self, name) is not None]
            if used:
                raise ValueError(f"{', '.join(used)} only allowed on ssh events")
        return self


def json_schema() -> dict[str, Any]:
    schema = Event.model_json_schema()
    schema["$id"] = "https://github.com/itzz-inbathamizhanS/QLure/docs/event.schema.json"
    schema["title"] = "Q-Lure event"
    return schema
