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


def _flags(args: list[str]) -> str:
    return "".join(a[1:] for a in args if a.startswith("-") and not a.startswith("--"))


def _ls_line(state: ShellState, path: str, name: str) -> str:
    if state.fs.is_dir(path):
        return f"drwxr-xr-x 2 {state.user} {state.user}  4096 Oct  8 18:20 {name}"
    size = len(state.fs.files.get(path, ""))
    return f"-rw-r--r-- 1 {state.user} {state.user} {size:>5} Oct  8 18:20 {name}"


def _cmd_ls(args: list[str], state: ShellState) -> str:
    # Flags such as -la are options, not paths (`ls -la` is the most common first command).
    flags = _flags(args)
    paths = [a for a in args if not a.startswith("-")]
    target = _resolve(state, paths[0]) if paths else state.cwd
    if state.fs.is_file(target):
        name = paths[0]
        return (_ls_line(state, target, name) if "l" in flags else name) + "\n"
    if not state.fs.is_dir(target):
        return f"ls: cannot access '{paths[0] if paths else '.'}': No such file or directory\n"
    names = state.fs.children(target)
    if "a" in flags:
        names = [".", "..", *names]
    else:
        names = [n for n in names if not n.startswith(".")]
    if "l" not in flags:
        return "\n".join(names) + "\n" if names else ""
    rows = [
        _ls_line(state, posixpath.join(target, n) if n not in (".", "..") else target, n)
        for n in names
    ]
    return f"total {4 * len(rows)}\n" + "".join(f"{r}\n" for r in rows)


def _cmd_cat(args: list[str], state: ShellState) -> str:
    out = []
    for arg in (a for a in args if not a.startswith("-") or a == "-"):
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


def _lines(text: str) -> list[str]:
    return text.splitlines()


def _file_args(args: list[str]) -> list[str]:
    plain, skip = [], False
    for arg in args:
        if skip:
            skip = False
        elif arg in ("-n", "-name"):
            skip = True  # the next word is this option's value, not a file
        elif not arg.startswith("-"):
            plain.append(arg)
    return plain


def _count(args: list[str], default: int = 10) -> int:
    for i, arg in enumerate(args):
        if arg == "-n" and i + 1 < len(args) and args[i + 1].isdigit():
            return int(args[i + 1])
        if arg.startswith("-") and arg[1:].isdigit():
            return int(arg[1:])
    return default


def _read_files(args: list[str], state: ShellState, name: str) -> list[tuple[str, str | None]]:
    out: list[tuple[str, str | None]] = []
    for arg in _file_args(args):
        path = _resolve(state, arg)
        out.append((arg, state.fs.files.get(path)))
    return out


def _cmd_head(args: list[str], state: ShellState) -> str:
    n, out = _count(args), []
    for arg, text in _read_files(args, state, "head"):
        if text is None:
            out.append(f"head: cannot open '{arg}' for reading: No such file or directory\n")
        else:
            out.append("".join(f"{ln}\n" for ln in _lines(text)[:n]))
    return "".join(out)


def _cmd_tail(args: list[str], state: ShellState) -> str:
    n, out = _count(args), []
    for arg, text in _read_files(args, state, "tail"):
        if text is None:
            out.append(f"tail: cannot open '{arg}' for reading: No such file or directory\n")
        else:
            out.append("".join(f"{ln}\n" for ln in _lines(text)[-n:]))
    return "".join(out)


def _cmd_wc(args: list[str], state: ShellState) -> str:
    out = []
    for arg, text in _read_files(args, state, "wc"):
        if text is None:
            out.append(f"wc: {arg}: No such file or directory\n")
        else:
            out.append(f"{len(_lines(text)):>4} {len(text.split()):>4} {len(text):>5} {arg}\n")
    return "".join(out)


def _cmd_grep(args: list[str], state: ShellState) -> str:
    plain = _file_args(args)
    if len(plain) < 2:
        return ""
    needle, out = plain[0].lower(), []
    for arg, text in _read_files(plain[1:], state, "grep"):
        if text is None:
            out.append(f"grep: {arg}: No such file or directory\n")
            continue
        prefix = f"{arg}:" if len(plain) > 2 else ""
        out += [f"{prefix}{ln}\n" for ln in _lines(text) if needle in ln.lower()]
    return "".join(out)


def _cmd_find(args: list[str], state: ShellState) -> str:
    root = _resolve(state, args[0]) if args and not args[0].startswith("-") else state.cwd
    prefix = root.rstrip("/") + "/"
    hits = sorted(path for path in state.fs.files if path.startswith(prefix))
    if "-name" in args and args.index("-name") + 1 < len(args):
        needle = args[args.index("-name") + 1].strip("*")
        hits = [h for h in hits if needle in posixpath.basename(h)]
    return "".join(f"{h}\n" for h in hits)


def _denied(name: str, args: list[str], state: ShellState) -> str:
    target = _file_args(args)[-1] if _file_args(args) else ""
    return f"{name}: cannot access '{target}': Permission denied\n"


def _cmd_which(args: list[str], state: ShellState) -> str:
    return "".join(f"/usr/bin/{a}\n" for a in _file_args(args) if a in COMMANDS or a == "cd")


def _cmd_groups(args: list[str], state: ShellState) -> str:
    return f"{state.user}\n"


def _cmd_w(args: list[str], state: ShellState) -> str:
    return (
        " 10:41:07 up 41 days,  3:12,  1 user,  load average: 0.08, 0.03, 0.01\n"
        "USER     TTY      FROM             LOGIN@   IDLE   WHAT\n"
        f"{state.user:<8} pts/0    10.20.0.5        10:40    0.00s w\n"
    )


def _cmd_who(args: list[str], state: ShellState) -> str:
    return f"{state.user}  pts/0        2026-10-09 10:40 (10.20.0.5)\n"


def _cmd_last(args: list[str], state: ShellState) -> str:
    return (
        f"{state.user}  pts/0        10.20.0.5        Thu Oct  8 18:22   still logged in\n"
        "reboot   system boot  5.15.0-101-gener Tue Aug 29 07:29   still running\n"
    )


def _cmd_netstat(args: list[str], state: ShellState) -> str:
    return (
        "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
        "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n"
        "tcp        0      0 10.20.0.14:22           10.20.0.5:51114         ESTABLISHED\n"
    )


def _cmd_systemctl(args: list[str], state: ShellState) -> str:
    return "Failed to connect to bus: Operation not permitted\n"


def _cmd_crontab(args: list[str], state: ShellState) -> str:
    if "-l" in args:
        return "0 2 * * * /home/deploy/app/backup.sh\n"
    return "usage: crontab [-l]\n"


def _cmd_ping(args: list[str], state: ShellState) -> str:
    host = (_file_args(args) or ["host"])[0]
    return f"ping: connect: Network is unreachable ({host})\n"


def _cmd_ssh(args: list[str], state: ShellState) -> str:
    host = (_file_args(args) or ["host"])[0]
    return f"ssh: connect to host {host} port 22: Network is unreachable\n"


def _cmd_nc(args: list[str], state: ShellState) -> str:
    return "nc: Network is unreachable\n"


def _cmd_python(args: list[str], state: ShellState) -> str:
    if "--version" in args or "-V" in args:
        return "Python 3.10.12\n"
    return "Python 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0] on linux\n>>> \n"


def _cmd_interpreter(args: list[str], state: ShellState) -> str:
    return ""  # a shell or interpreter that does nothing visible; nothing is ever run


def _cmd_su(args: list[str], state: ShellState) -> str:
    return "su: Authentication failure\n"


def _cmd_passwd(args: list[str], state: ShellState) -> str:
    return (
        "passwd: Authentication token manipulation error\n"
        f"passwd: password unchanged ({state.user})\n"
    )


def _cmd_apt(args: list[str], state: ShellState) -> str:
    return (
        "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)\n"
    )


def _cmd_docker(args: list[str], state: ShellState) -> str:
    return (
        "permission denied while trying to connect to the Docker daemon socket at "
        "unix:///var/run/docker.sock\n"
    )


def _cmd_git(args: list[str], state: ShellState) -> str:
    return "fatal: not a git repository (or any of the parent directories): .git\n"


def _cmd_tar(args: list[str], state: ShellState) -> str:
    return "tar: Cannot open: Permission denied\n"


def _cmd_export(args: list[str], state: ShellState) -> str:
    return ""


def _cmd_man(args: list[str], state: ShellState) -> str:
    topic = (_file_args(args) or [""])[0]
    return f"No manual entry for {topic}\n" if topic else "What manual page do you want?\n"


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
    "head": _cmd_head,
    "tail": _cmd_tail,
    "wc": _cmd_wc,
    "grep": _cmd_grep,
    "find": _cmd_find,
    "which": _cmd_which,
    "groups": _cmd_groups,
    "w": _cmd_w,
    "who": _cmd_who,
    "last": _cmd_last,
    "netstat": _cmd_netstat,
    "ss": _cmd_netstat,
    "systemctl": _cmd_systemctl,
    "crontab": _cmd_crontab,
    "ping": _cmd_ping,
    "ssh": _cmd_ssh,
    "nc": _cmd_nc,
    "python": _cmd_python,
    "python3": _cmd_python,
    "bash": _cmd_interpreter,
    "sh": _cmd_interpreter,
    "perl": _cmd_interpreter,
    "su": _cmd_su,
    "passwd": _cmd_passwd,
    "apt": _cmd_apt,
    "apt-get": _cmd_apt,
    "docker": _cmd_docker,
    "git": _cmd_git,
    "tar": _cmd_tar,
    "export": _cmd_export,
    "man": _cmd_man,
    "touch": lambda args, state: _denied("touch", args, state),
    "mkdir": lambda args, state: _denied("mkdir", args, state),
    "rm": lambda args, state: _denied("rm", args, state),
    "mv": lambda args, state: _denied("mv", args, state),
    "cp": lambda args, state: _denied("cp", args, state),
    "chmod": lambda args, state: _denied("chmod", args, state),
    "chown": lambda args, state: _denied("chown", args, state),
    "wget": lambda args, state: _cmd_network_fetch(args, state, "wget"),
    "curl": lambda args, state: _cmd_network_fetch(args, state, "curl"),
}


FILTERS = {"grep", "head", "tail", "wc"}
_OPERATORS = (";", "&&", "||", "|")


def _split(line: str) -> list[tuple[str, list[str]]]:
    """Split a line into (operator before it, argv) parts on ; && || and |, outside quotes."""
    lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|")
    lexer.whitespace_split = True
    parts: list[tuple[str, list[str]]] = []
    joiner, argv = ";", []
    for token in lexer:
        if token in _OPERATORS:
            parts.append((joiner, argv))
            joiner, argv = token, []
        elif set(token) <= set(";&|"):
            raise ValueError(token)  # e.g. a lone & or |||
        else:
            argv.append(token)
    parts.append((joiner, argv))
    return parts


def _filter(name: str, args: list[str], text: str) -> str:
    """grep, head, tail or wc reading piped text instead of a file."""
    lines = _lines(text)
    if name == "grep":
        plain = _file_args(args)
        needle = plain[0].lower() if plain else ""
        return "".join(f"{ln}\n" for ln in lines if needle in ln.lower())
    if name == "head":
        return "".join(f"{ln}\n" for ln in lines[: _count(args)])
    if name == "tail":
        return "".join(f"{ln}\n" for ln in lines[-_count(args) :])
    return f"{len(lines):>7} {len(text.split()):>7} {len(text):>7}\n"


def run(line: str, state: ShellState) -> str:
    """Answer one command line. Returns the text the terminal should show.

    `a; b`, `a && b`, `a || b` and `a | grep x` work the way a visitor expects: each part is
    answered from the same tables, and a piped grep, head, tail or wc filters the text before it.
    """
    try:
        parts = _split(line)
    except ValueError:
        return "bash: syntax error near unexpected token\n"
    if len(parts) == 1:
        return _run_one(parts[0][1], state)
    out: list[str] = []
    piped: str | None = None
    for i, (joiner, argv) in enumerate(parts):
        if not argv:
            return f"bash: syntax error near unexpected token `{parts[i][0] if i else ';'}'\n"
        following = parts[i + 1][0] if i + 1 < len(parts) else ";"
        if (
            joiner == "|"
            and piped is not None
            and argv[0] in FILTERS
            and len(_file_args(argv[1:])) <= (argv[0] == "grep")
        ):
            text = _filter(argv[0], argv[1:], piped)
        else:
            text = _run_one(argv, state)
        if following == "|":
            piped = text
            continue
        piped = None
        out.append(text)
    return "".join(out)


def _run_one(argv: list[str], state: ShellState) -> str:
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
