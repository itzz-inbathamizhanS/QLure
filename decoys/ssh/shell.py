"""Fake shell for the SSH decoy.

Each typed command is looked up in COMMANDS and answered from fixed text or the fake
file tree. Nothing is executed: no subprocess, no exec, no eval.
"""

from __future__ import annotations

import posixpath
import shlex
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from decoys import honeytokens

FAKEFS_FILE = Path(__file__).parent.parent / "fakefs" / "fs.yaml"
HOME = "/home/deploy"
BANNER = (
    "Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-101-generic x86_64)\n"
    "Last login: Thu Oct  8 18:22:41 2026 from 10.20.0.5\n"
)


@dataclass
class FakeFS:
    hostname: str
    files: dict[str, str]

    def is_file(self, path: str) -> bool:
        return path in self.files

    def is_dir(self, path: str) -> bool:
        if path == "/":
            return True
        prefix = path.rstrip("/") + "/"
        return any(name.startswith(prefix) for name in self.files)

    def children(self, path: str) -> list[str]:
        prefix = path.rstrip("/") + "/"
        names = {
            name[len(prefix) :].split("/")[0] for name in self.files if name.startswith(prefix)
        }
        return sorted(names)


@lru_cache(maxsize=1)
def load_fs() -> FakeFS:
    data = yaml.safe_load(FAKEFS_FILE.read_text(encoding="utf-8"))
    api_key = honeytokens.get("ht-api-001")["value"]
    files = {path: text.replace("{{ht-api-001}}", api_key) for path, text in data["files"].items()}
    return FakeFS(hostname=data["hostname"], files=files)


@dataclass
class ShellState:
    user: str
    fs: FakeFS = field(default_factory=load_fs)
    cwd: str = HOME
    history: list[str] = field(default_factory=list)


def _resolve(state: ShellState, arg: str) -> str:
    if arg == "~" or arg.startswith("~/"):
        arg = HOME + arg[1:]
    return posixpath.normpath(posixpath.join(state.cwd, arg))


def _cmd_whoami(args: list[str], state: ShellState) -> str:
    return f"{state.user}\n"


def _cmd_id(args: list[str], state: ShellState) -> str:
    return f"uid=1001({state.user}) gid=1001({state.user}) groups=1001({state.user})\n"


def _cmd_hostname(args: list[str], state: ShellState) -> str:
    return f"{state.fs.hostname}\n"


def _cmd_uname(args: list[str], state: ShellState) -> str:
    if "-a" in args:
        return f"Linux {state.fs.hostname} 5.15.0-101-generic #111-Ubuntu SMP x86_64 GNU/Linux\n"
    return "Linux\n"


def _cmd_pwd(args: list[str], state: ShellState) -> str:
    return f"{state.cwd}\n"


def _cmd_ls(args: list[str], state: ShellState) -> str:
    target = _resolve(state, args[0]) if args else state.cwd
    if state.fs.is_file(target):
        return f"{posixpath.basename(target)}\n"
    if not state.fs.is_dir(target):
        return f"ls: cannot access '{args[0] if args else '.'}': No such file or directory\n"
    names = state.fs.children(target)
    return "\n".join(names) + "\n" if names else ""


def _cmd_cat(args: list[str], state: ShellState) -> str:
    out = []
    for arg in args:
        path = _resolve(state, arg)
        if path in state.fs.files:
            out.append(state.fs.files[path])
        elif state.fs.is_dir(path):
            out.append(f"cat: {arg}: Is a directory\n")
        else:
            out.append(f"cat: {arg}: No such file or directory\n")
    return "".join(out)


def _cmd_echo(args: list[str], state: ShellState) -> str:
    return " ".join(args) + "\n"


def _cmd_history(args: list[str], state: ShellState) -> str:
    return "".join(f"{i:>5}  {line}\n" for i, line in enumerate(state.history, 1))


def _cmd_date(args: list[str], state: ShellState) -> str:
    return datetime.now(UTC).strftime("%a %b %d %H:%M:%S UTC %Y") + "\n"


def _cmd_uptime(args: list[str], state: ShellState) -> str:
    now = datetime.now(UTC).strftime("%H:%M:%S")
    return f" {now} up 41 days,  3:12,  1 user,  load average: 0.08, 0.03, 0.01\n"


def _cmd_df(args: list[str], state: ShellState) -> str:
    return (
        "Filesystem      Size  Used Avail Use% Mounted on\n"
        "/dev/sda1        40G   14G   24G  37% /\n"
    )


def _cmd_free(args: list[str], state: ShellState) -> str:
    return (
        "               total        used        free      shared  buff/cache   available\n"
        "Mem:           7.7Gi       2.1Gi       1.9Gi       112Mi       3.7Gi       5.2Gi\n"
    )


def _cmd_ps(args: list[str], state: ShellState) -> str:
    return "  PID TTY          TIME CMD\n 1421 pts/0    00:00:00 bash\n 1502 pts/0    00:00:00 ps\n"


def _cmd_env(args: list[str], state: ShellState) -> str:
    return (
        f"USER={state.user}\nHOME={HOME}\nSHELL=/bin/bash\n"
        "PATH=/usr/local/bin:/usr/bin:/bin\nLANG=en_US.UTF-8\n"
    )


def _cmd_ip(args: list[str], state: ShellState) -> str:
    return "2: eth0: inet 10.20.0.14/24 brd 10.20.0.255 scope global eth0\n"


def _cmd_network_fetch(args: list[str], state: ShellState, name: str) -> str:
    # The decoy has no route out, so any download fails the way it would offline.
    url = next((a for a in args if "://" in a or "." in a), "")
    if name == "curl":
        return f"curl: (6) Could not resolve host: {url}\n"
    return f"wget: unable to resolve host address '{url}'\n"


def _cmd_sudo(args: list[str], state: ShellState) -> str:
    return f"{state.user} is not in the sudoers file. This incident will be reported.\n"


def _cmd_clear(args: list[str], state: ShellState) -> str:
    return "\x1b[2J\x1b[H"


COMMANDS: dict[str, Callable[[list[str], ShellState], str]] = {
    "whoami": _cmd_whoami,
    "id": _cmd_id,
    "hostname": _cmd_hostname,
    "uname": _cmd_uname,
    "pwd": _cmd_pwd,
    "ls": _cmd_ls,
    "cat": _cmd_cat,
    "echo": _cmd_echo,
    "history": _cmd_history,
    "date": _cmd_date,
    "uptime": _cmd_uptime,
    "df": _cmd_df,
    "free": _cmd_free,
    "ps": _cmd_ps,
    "env": _cmd_env,
    "ip": _cmd_ip,
    "ifconfig": _cmd_ip,
    "sudo": _cmd_sudo,
    "clear": _cmd_clear,
    "wget": lambda args, state: _cmd_network_fetch(args, state, "wget"),
    "curl": lambda args, state: _cmd_network_fetch(args, state, "curl"),
}


def run(line: str, state: ShellState) -> str:
    """Answer one command line. Returns the text the terminal should show."""
    try:
        argv = shlex.split(line)
    except ValueError:
        return "bash: syntax error: unexpected end of file\n"
    if not argv:
        return ""
    name, args = argv[0], argv[1:]
    if name == "cd":
        target = _resolve(state, args[0]) if args else HOME
        if state.fs.is_dir(target):
            state.cwd = target
            return ""
        return f"bash: cd: {args[0] if args else '~'}: No such file or directory\n"
    handler = COMMANDS.get(name)
    if handler is None:
        return f"bash: {name}: command not found\n"
    return handler(args, state)


def _display_cwd(state: ShellState) -> str:
    return "~" if state.cwd == HOME else state.cwd


async def _read_line(process: Any) -> str | None:
    """Read one typed line, echoing it back. None means the client hung up."""
    typed: list[str] = []
    while True:
        ch = await process.stdin.read(1)
        if not ch:
            return None
        if ch in ("\r", "\n"):
            process.stdout.write("\r\n")
            return "".join(typed)
        if ch == "\x04":
            return None
        if ch in ("\x7f", "\b"):
            if typed:
                typed.pop()
                process.stdout.write("\b \b")
            continue
        if ch < " ":
            continue
        typed.append(ch)
        process.stdout.write(ch)


async def run_session(
    process: Any, state: ShellState, on_command: Callable[[str, str], None]
) -> None:
    """Drive one SSH channel: either a single `ssh host command`, or an interactive shell."""
    if process.command:
        output = run(process.command, state)
        on_command(process.command, output)
        process.stdout.write(output)  # no terminal attached, so plain newlines
        process.exit(0)
        return

    process.stdout.write(BANNER.replace("\n", "\r\n"))
    while True:
        process.stdout.write(f"{state.user}@{state.fs.hostname}:{_display_cwd(state)}$ ")
        line = await _read_line(process)
        if line is None:
            break
        stripped = line.strip()
        if stripped in ("exit", "logout"):
            process.stdout.write("logout\r\n")
            break
        if not stripped:
            continue
        state.history.append(stripped)
        output = run(stripped, state)
        on_command(stripped, output)
        process.stdout.write(output.replace("\n", "\r\n"))
    process.exit(0)
