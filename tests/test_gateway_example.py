"""The example nginx config and the deployment guide: structure, placeholders and links."""

import ipaddress
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
CONF = REPO / "gateway" / "nginx.real-and-decoy.example.conf"
COMPOSE = REPO / "docker-compose.yml"
GUIDE = REPO / "docs" / "DEPLOY_ALONGSIDE_REAL_SERVICE.md"
FIREWALL = REPO / "docs" / "examples" / "firewall-allowlist.md"
NEW_FILES = (CONF, GUIDE, FIREWALL)
LINKING_FILES = (
    REPO / "README.md",
    REPO / "docs" / "architecture" / "03-decoys.md",
    REPO / "docs" / "architecture" / "07-security-model.md",
    REPO / "docs" / "ROADMAP.md",
)

REAL_HOST = "app.example.com"
# Paths the decoy web answers. Only the default servers may route these.
SCANNER_TOKENS = (
    ".env",
    ".git/",
    "wp-login.php",
    "wp-admin/",
    "phpmyadmin",
    "server-status",
    "backup/",
)
DECOY_PORTS = {22, 21, 3306, 6379}
# Documentation ranges and RFC1918 placeholders. 0.0.0.0 and 127.0.0.1 are bind or loopback
# addresses, not hosts, so they are allowed too.
ALLOWED_NETS = [
    ipaddress.ip_network(net)
    for net in (
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "0.0.0.0/32",
    )
]
LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
PATH_TOKEN = re.compile(r"`([\w./-]+\.(?:conf|md|py|yml|yaml|json|toml))`")
IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
BANNED_NAMES = re.compile(
    r"\b(claude|anthropic|openai|chatgpt|copilot|gemini|gpt|llm|ai)\b", re.IGNORECASE
)


@dataclass
class Block:
    header: str
    directives: list[str] = field(default_factory=list)
    children: list["Block"] = field(default_factory=list)


def _code_lines(text: str) -> list[str]:
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def parse_nginx(text: str) -> Block:
    """Build a tree of blocks. Fails on an unbalanced brace or a directive without ';'."""
    root = Block("root")
    stack = [root]
    for number, line in enumerate(_code_lines(text), start=1):
        assert "#" not in line, f"line {number}: no inline comments in the example: {line}"
        if line.endswith("{"):
            child = Block(line[:-1].strip())
            stack[-1].children.append(child)
            stack.append(child)
        elif line == "}":
            assert len(stack) > 1, f"line {number}: '}}' without a matching block"
            stack.pop()
        else:
            assert line.endswith(";"), f"line {number}: directive must end with ';': {line}"
            stack[-1].directives.append(line)
    assert len(stack) == 1, "a block is never closed"
    return root


def _child(block: Block, header: str) -> Block:
    found = [child for child in block.children if child.header == header]
    assert len(found) == 1, f"expected one '{header}' block"
    return found[0]


def _servers(block: Block) -> list[Block]:
    return [child for child in block.children if child.header == "server"]


def _locations(server: Block) -> list[Block]:
    return [child for child in server.children if child.header.startswith("location")]


def _location_target(header: str) -> str:
    return header.removeprefix("location").strip()


def _upstreams(block: Block) -> list[str]:
    targets = []
    for directive in block.directives:
        if directive.startswith("proxy_pass "):
            targets.append(directive.split()[1].rstrip(";"))
    for child in block.children:
        targets.extend(_upstreams(child))
    return targets


def _host_of(target: str) -> str:
    """Host part of a proxy_pass target such as https://real-app.internal:8443."""
    without_scheme = re.sub(r"^https?://", "", target)
    return without_scheme.split("/")[0].rsplit(":", 1)[0]


def _slug(heading: str) -> str:
    """GitHub-style anchor for a heading."""
    lowered = heading.strip().lower()
    return re.sub(r"[^\w\- ]", "", lowered).replace(" ", "-")


def _anchors(path: Path) -> set[str]:
    headings = re.findall(r"^#{1,6}\s+(.*)$", path.read_text(encoding="utf-8"), re.MULTILINE)
    return {_slug(heading) for heading in headings}


def _assert_links_resolve(path: Path) -> list[str]:
    """Check every relative link in a Markdown file. Returns the relative links found."""
    relative = []
    for target in LINK.findall(path.read_text(encoding="utf-8")):
        if target.startswith(("http://", "https://", "mailto:")):
            continue
        relative.append(target)
        file_part, _, anchor = target.partition("#")
        dest = path.parent / file_part if file_part else path
        assert dest.exists(), f"{path.name}: broken link {target}"
        if anchor and dest.suffix == ".md":
            assert anchor in _anchors(dest), f"{path.name}: no heading for {target}"
    return relative


def _assert_documentation_addresses(text: str, name: str) -> None:
    for address in IPV4.findall(text):
        ip = ipaddress.ip_address(address)
        assert any(ip in net for net in ALLOWED_NETS), f"{name}: non-placeholder IP {address}"


def test_example_is_marked_and_not_used_by_compose():
    text = CONF.read_text(encoding="utf-8")
    assert text.splitlines()[0].startswith("# EXAMPLE ONLY")
    assert "not used by docker-compose.yml" in text.splitlines()[0].lower()
    assert "nginx.real-and-decoy" not in COMPOSE.read_text(encoding="utf-8")


def test_braces_balance_and_directives_end_correctly():
    text = CONF.read_text(encoding="utf-8")
    code = _code_lines(text)
    for line in code:
        assert line.endswith((";", "{", "}")), f"bad line ending: {line}"
    joined = "\n".join(code)
    assert joined.count("{") == joined.count("}")
    parse_nginx(text)


def test_real_hostname_server_has_no_decoy_paths_or_upstream():
    root = parse_nginx(CONF.read_text(encoding="utf-8"))
    http = _child(root, "http")
    real = [s for s in _servers(http) if f"server_name {REAL_HOST};" in s.directives]
    assert len(real) >= 2, "expected the real HTTPS server and its HTTP redirect"
    for server in real:
        for directive in server.directives:
            assert "decoy" not in directive.lower(), directive
        for location in _locations(server):
            target = _location_target(location.header)
            for token in SCANNER_TOKENS:
                assert token not in target, f"decoy path {token} in the real server"
            for directive in location.directives:
                assert "decoy" not in directive.lower(), directive


def test_real_https_server_proxies_to_the_real_upstream():
    root = parse_nginx(CONF.read_text(encoding="utf-8"))
    http = _child(root, "http")
    real = [s for s in _servers(http) if "listen 443 ssl;" in s.directives]
    assert len(real) == 1
    assert _upstreams(real[0]) == ["https://real-app.internal:8443"]


def test_default_servers_proxy_to_the_decoy_and_carry_scanner_paths():
    root = parse_nginx(CONF.read_text(encoding="utf-8"))
    http = _child(root, "http")
    defaults = [s for s in _servers(http) if any("default_server" in d for d in s.directives)]
    ports = {int(re.search(r"listen (\d+)", " ".join(s.directives)).group(1)) for s in defaults}
    assert ports == {80, 443}
    for server in defaults:
        upstreams = _upstreams(server)
        assert upstreams, "a default server must proxy somewhere"
        for target in upstreams:
            assert re.fullmatch(r"https?://decoy-[a-z]+:\d+", target), target
        # Unescape regex dots and slashes so "wp-login\.php" is compared as "wp-login.php".
        paths = " ".join(_location_target(loc.header) for loc in _locations(server))
        paths = paths.replace("\\", "")
        for token in SCANNER_TOKENS:
            assert token in paths, f"default server has no location for {token}"


def test_stream_block_uses_proxy_protocol_and_decoy_upstreams_only():
    root = parse_nginx(CONF.read_text(encoding="utf-8"))
    stream = _child(root, "stream")
    servers = _servers(stream)
    listened = set()
    for server in servers:
        assert "proxy_protocol on;" in server.directives, server.directives
        for target in _upstreams(server):
            assert re.fullmatch(r"decoy-[a-z]+:\d+", target), target
        listened.add(int(re.search(r"listen (\d+)", " ".join(server.directives)).group(1)))
    assert listened == DECOY_PORTS


def test_hosts_are_placeholders_and_addresses_are_documentation_ranges():
    text = CONF.read_text(encoding="utf-8")
    root = parse_nginx(text)
    for target in _upstreams(root):
        host = _host_of(target)
        assert host.startswith("decoy-") or host.endswith((".example.com", ".internal")), target
    for directive in _code_lines(text):
        if directive.startswith("server_name "):
            value = directive.split(None, 1)[1].rstrip(";")
            assert value in ("_", REAL_HOST), directive
    for name, content in ((path.name, path.read_text(encoding="utf-8")) for path in NEW_FILES):
        _assert_documentation_addresses(content, name)


def test_new_files_do_not_name_tools_or_vendors():
    for path in NEW_FILES:
        match = BANNED_NAMES.search(path.read_text(encoding="utf-8"))
        assert match is None, f"{path.name}: remove {match.group(0)!r}"


def test_guide_relative_links_resolve():
    links = _assert_links_resolve(GUIDE)
    assert links, "the guide should link to other files"


def test_firewall_example_links_resolve():
    _assert_links_resolve(FIREWALL)


def test_linking_files_point_at_the_guide():
    for path in LINKING_FILES:
        targets = LINK.findall(path.read_text(encoding="utf-8"))
        links = [t for t in targets if "DEPLOY_ALONGSIDE" in t]
        assert links, f"{path.name} does not link to the guide"
        for target in links:
            assert (path.parent / target.partition("#")[0]).exists(), f"{path.name}: {target}"


def test_repo_paths_named_in_the_guide_exist():
    text = GUIDE.read_text(encoding="utf-8") + FIREWALL.read_text(encoding="utf-8")
    assert "gateway/nginx.real-and-decoy.example.conf" in text
    assert "examples/firewall-allowlist.md" in text
    for token in PATH_TOKEN.findall(text):
        first = token.split("/", 1)[0]
        # Only check paths rooted in the repository. Runtime folders such as data/ are not in git.
        if (REPO / first).exists():
            assert (REPO / token).exists(), f"named path does not exist: {token}"


@pytest.mark.skipif(shutil.which("nginx") is None, reason="nginx is not installed")
def test_nginx_config_test_with_placeholder_certificates(tmp_path):
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("openssl is needed to make placeholder certificates")
    text = CONF.read_text(encoding="utf-8")
    stems = {name.rsplit(".", 1)[0] for name in re.findall(r"/etc/ssl/example/([\w.-]+)", text)}
    for stem in sorted(stems):
        try:
            subprocess.run(  # noqa: S603
                [
                    openssl,
                    "req",
                    "-x509",
                    "-newkey",
                    "ec",
                    "-pkeyopt",
                    "ec_paramgen_curve:prime256v1",
                    "-nodes",
                    "-keyout",
                    str(tmp_path / f"{stem}.key"),
                    "-out",
                    str(tmp_path / f"{stem}.pem"),
                    "-days",
                    "1",
                    "-subj",
                    "/CN=example.test",
                ],
                check=True,
                capture_output=True,
                timeout=60,
            )
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pytest.skip("could not make placeholder certificates")
    # Point the certificate paths at the temp files and the upstream names at loopback, so nginx
    # checks the syntax without needing the real names to resolve.
    text = re.sub(r"\b(real-app\.internal|decoy-[a-z]+)\b", "127.0.0.1", text)
    text = text.replace("/etc/ssl/example/", f"{tmp_path}/")
    (tmp_path / "logs").mkdir()
    conf = tmp_path / "nginx.conf"
    conf.write_text(text, encoding="utf-8")
    nginx = shutil.which("nginx")
    result = subprocess.run(  # noqa: S603
        [nginx, "-t", "-c", str(conf), "-p", str(tmp_path)],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    if result.returncode != 0 and "Permission denied" in result.stderr:
        pytest.skip("this user cannot bind the privileged ports that nginx -t checks")
    if result.returncode != 0 and 'unknown directive "stream"' in result.stderr:
        pytest.skip("this nginx build has no stream module")
    assert result.returncode == 0, result.stderr
