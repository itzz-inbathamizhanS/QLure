"""Fake Docker Engine API decoy (port 2375, plain HTTP like an exposed Docker daemon).

Every reply is a fixed JSON document. Creating a container, pulling an image or running exec
returns a plausible success with a FAKE id so a miner dropper keeps going, but nothing is ever
executed, pulled, started or stored: no handler touches a subprocess, the network or a file.
Each request is logged as an http_request with the first 2 KB of its body.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse

from decoys.common import fingerprint, read_capped, replay_ts
from decoys.ssh.shell import load_fs
from decoys.web.app import FP_HEADERS, LOGGED_HEADERS, _body_summary
from qlure.events import Action, Service, emit

API_VERSION = "1.43"
ENGINE_VERSION = "24.0.7"
ANY_ADDR = "0.0.0.0"  # noqa: S104  (a fake published-port address in a reply)
SERVER_HEADER = f"Docker/{ENGINE_VERSION} (linux)"
_VERSION_PREFIX = re.compile(r"^/v\d+\.\d+(?=/|$)")
_CONTAINER_ACTION = re.compile(r"^/containers/[A-Za-z0-9_.-]{1,64}/(start|exec)$")
_EXEC_START = re.compile(r"^/exec/[A-Za-z0-9_.-]{1,64}/start$")

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


def _fake_id(kind: str, body: bytes) -> str:
    """A 64-hex id that looks like Docker's. It names nothing: no object is ever created."""
    return hashlib.sha256(b"qlure-fake-" + kind.encode() + body).hexdigest()


def _version() -> dict[str, Any]:
    return {
        "Platform": {"Name": "Docker Engine - Community"},
        "Components": [
            {
                "Name": "Engine",
                "Version": ENGINE_VERSION,
                "Details": {
                    "ApiVersion": API_VERSION,
                    "Arch": "amd64",
                    "BuildTime": "2023-10-26T09:08:17.000000000+00:00",
                    "Experimental": "false",
                    "GitCommit": "311b9ff",
                    "GoVersion": "go1.20.10",
                    "KernelVersion": "5.15.0-91-generic",
                    "MinAPIVersion": "1.12",
                    "Os": "linux",
                },
            }
        ],
        "Version": ENGINE_VERSION,
        "ApiVersion": API_VERSION,
        "MinAPIVersion": "1.12",
        "GitCommit": "311b9ff",
        "GoVersion": "go1.20.10",
        "Os": "linux",
        "Arch": "amd64",
        "KernelVersion": "5.15.0-91-generic",
        "BuildTime": "2023-10-26T09:08:17.000000000+00:00",
    }


def _info() -> dict[str, Any]:
    return {
        "ID": "7T3W:5KJA:QX2B:HE4P:ZLNY:6V2R:OCDM:UJ3F:WQ5A:XB7K:4TGE:PI2S",
        "Containers": 3,
        "ContainersRunning": 3,
        "ContainersPaused": 0,
        "ContainersStopped": 0,
        "Images": 3,
        "Driver": "overlay2",
        "DockerRootDir": "/var/lib/docker",
        "LoggingDriver": "json-file",
        "CgroupDriver": "systemd",
        "CgroupVersion": "2",
        "KernelVersion": "5.15.0-91-generic",
        "OperatingSystem": "Ubuntu 22.04.3 LTS",
        "OSType": "linux",
        "Architecture": "x86_64",
        "NCPU": 4,
        "MemTotal": 8332034048,
        "Name": load_fs().hostname,
        "ServerVersion": ENGINE_VERSION,
        "SecurityOptions": ["name=apparmor", "name=seccomp,profile=builtin", "name=cgroupns"],
        "Swarm": {"NodeID": "", "NodeAddr": "", "LocalNodeState": "inactive"},
    }


def _containers() -> list[dict[str, Any]]:
    def one(
        name: str, image: str, digest: str, command: str, ports: list[dict[str, Any]], age: int
    ):
        return {
            "Id": hashlib.sha256(b"qlure-fake-listing-" + name.encode()).hexdigest(),
            "Names": [f"/{name}"],
            "Image": image,
            "ImageID": f"sha256:{digest * 8}",
            "Command": command,
            "Created": 1696800000 + age,
            "Ports": ports,
            "Labels": {},
            "State": "running",
            "Status": "Up 6 weeks",
            "HostConfig": {"NetworkMode": "default"},
            "Mounts": [],
        }

    return [
        one(
            "veltrix-nginx",
            "nginx:1.24",
            "a1b2c3d4",
            "/docker-entrypoint.sh nginx -g 'daemon off;'",
            [{"IP": ANY_ADDR, "PrivatePort": 80, "PublicPort": 80, "Type": "tcp"}],
            0,
        ),
        one(
            "veltrix-postgres",
            "postgres:15",
            "e5f60718",
            "docker-entrypoint.sh postgres",
            [{"PrivatePort": 5432, "Type": "tcp"}],
            60,
        ),
        one(
            "veltrix-app",
            "veltrix/app:2.4.1",
            "92a3b4c5",
            "gunicorn app:create_app()",
            [{"PrivatePort": 8000, "Type": "tcp"}],
            120,
        ),
    ]


def _images() -> list[dict[str, Any]]:
    rows = [
        ("nginx:1.24", "a1b2c3d4", 142_000_000),
        ("postgres:15", "e5f60718", 412_000_000),
        ("veltrix/app:2.4.1", "92a3b4c5", 238_000_000),
    ]
    return [
        {
            "Id": f"sha256:{digest * 8}",
            "ParentId": "",
            "RepoTags": [tag],
            "RepoDigests": [],
            "Created": 1696000000,
            "Size": size,
            "VirtualSize": size,
            "Labels": None,
            "Containers": 1,
        }
        for tag, digest, size in rows
    ]


def _not_found() -> Response:
    return JSONResponse({"message": "page not found"}, status_code=404)


def _reply(method: str, path: str, body: bytes) -> Response:
    """The fixed reply for one request. `path` has no version prefix."""
    if method in ("GET", "HEAD") and path == "/_ping":
        return PlainTextResponse("OK" if method == "GET" else "")
    if method == "GET":
        fixed = {
            "/version": _version,
            "/info": _info,
            "/containers/json": _containers,
            "/images/json": _images,
        }.get(path)
        return JSONResponse(fixed()) if fixed else _not_found()
    if method != "POST":
        return _not_found()
    if path == "/containers/create":
        return JSONResponse({"Id": _fake_id("container", body), "Warnings": []}, status_code=201)
    if path == "/images/create":
        lines = [
            {"status": "Pulling from library/alpine", "id": "latest"},
            {"status": "Status: Downloaded newer image for alpine:latest"},
        ]
        return Response(
            "\n".join(json.dumps(x) for x in lines) + "\n", media_type="application/json"
        )
    if _EXEC_START.match(path):
        return Response(b"", media_type="application/vnd.docker.raw-stream")
    match = _CONTAINER_ACTION.match(path)
    if match and match.group(1) == "start":
        return Response(status_code=204)
    if match:  # exec: only an id comes back; the command is never run
        return JSONResponse({"Id": _fake_id("exec", body + path.encode())}, status_code=201)
    return _not_found()


@app.middleware("http")
async def observe(request: Request, call_next):
    body = await read_capped(request)
    if body is None:
        body = b""
        response: Response = PlainTextResponse("413 Request Entity Too Large", status_code=413)
    else:
        request.state.body = body
        response = await call_next(request)
    response.headers["server"] = SERVER_HEADER
    response.headers["api-version"] = API_VERSION
    response.headers["docker-experimental"] = "false"
    response.headers["ostype"] = "linux"

    emit(
        {
            "service": Service.DOCKER,
            "src_ip": request.client.host if request.client else "0.0.0.0",  # noqa: S104
            "src_port": (request.client.port or None) if request.client else None,
            "client_fp": fingerprint(*(request.headers.get(name, "") for name in FP_HEADERS)),
            "session_id": _session_id(request),
            "replay_ts": replay_ts(request.headers),
            "action": Action.HTTP_REQUEST,
            "request": {
                "method": request.method,
                "path": request.url.path,
                "query": request.url.query,
                "http_version": request.scope.get("http_version"),
                "headers": {k: v for k, v in request.headers.items() if k in LOGGED_HEADERS},
                **_body_summary(body),
            },
            "response": {"status": response.status_code},
        }
    )
    return response


def _session_id(request: Request) -> str:
    """One id per source address and client: a dropper's requests stay in one session."""
    ip = request.client.host if request.client else "0.0.0.0"  # noqa: S104
    return "dk-" + fingerprint(ip, request.headers.get("user-agent", ""))


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"])
async def handle(request: Request, path: str) -> Response:
    # The middleware has already consumed the body (kept in request.state); it only feeds the
    # fake id, which is a hash of it.
    body = getattr(request.state, "body", b"")
    return _reply(request.method, _VERSION_PREFIX.sub("", request.url.path), body)
