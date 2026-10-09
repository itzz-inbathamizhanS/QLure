"""P1.5 fake filesystem and honeytokens, and the P1.3 web content files that routes will use."""

import re
from pathlib import Path

import yaml

from decoys import honeytokens
from decoys.ssh.shell import BANNER, FAKEFS_FILE, ShellState, load_fs, run

DECOYS = Path(__file__).resolve().parents[2] / "decoys"
TEMPLATES = DECOYS / "web" / "templates"
NEW_IDS = ("ht-git-001", "ht-sshkey-001", "ht-redis-001", "ht-canary-001")
KEY_MARKER = "BEGIN DECOY PRIVATE KEY"
REAL_KEY = re.compile(r"BEGIN (OPENSSH |RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY")
NEW_FS_PATHS = (
    "/home/deploy/.ssh/authorized_keys",
    "/home/deploy/.ssh/known_hosts",
    "/home/deploy/.ssh/id_rsa",
    "/home/deploy/app/backup.sh",
    "/home/deploy/app/config.yaml",
    "/var/log/auth.log",
    "/proc/cpuinfo",
)


def _value(token_id: str) -> str:
    return honeytokens.get(token_id)["value"]


def test_new_honeytokens_load_with_their_ids_and_kinds():
    tokens = honeytokens.load()
    assert set(NEW_IDS) <= set(tokens)
    assert tokens["ht-git-001"]["kind"] == "git_token"
    assert tokens["ht-sshkey-001"]["kind"] == "ssh_private_key"
    assert tokens["ht-redis-001"]["kind"] == "redis_password"
    assert tokens["ht-redis-001"]["accepted_by"] == "redis"
    assert tokens["ht-canary-001"]["kind"] == "canary_url"


def test_every_planted_value_contains_decoy():
    for token in honeytokens.load().values():
        assert "decoy" in token["value"].lower(), token["id"]


def test_redis_password_matches_on_its_kind():
    value = _value("ht-redis-001")
    assert honeytokens.find("redis_password", value)["id"] == "ht-redis-001"
    assert honeytokens.find("ssh_password", value) is None


def test_canary_url_is_on_the_decoy_domain():
    assert _value("ht-canary-001").startswith("https://canary.decoy.example/")


def test_no_real_private_key_material_in_decoys():
    assert KEY_MARKER in _value("ht-sshkey-001")
    texts = [token["value"] for token in honeytokens.load().values()]
    texts += [text for text in load_fs().files.values()]
    for text in texts:
        assert not REAL_KEY.search(text)


def test_new_fakefs_paths_exist_and_parse_with_the_shell_loader():
    raw = yaml.safe_load(FAKEFS_FILE.read_text(encoding="utf-8"))
    assert raw["hostname"] == "veltrix-app-01"
    fs = load_fs()
    for path in NEW_FS_PATHS:
        assert fs.is_file(path), path
        assert fs.files[path].strip(), path


def test_shell_shows_the_new_files():
    state = ShellState(user="deploy")
    assert "ssh-ed25519" in run("cat ~/.ssh/authorized_keys", state)
    assert "git.example.internal" in run("cat ~/.ssh/known_hosts", state)
    assert KEY_MARKER in run("cat ~/.ssh/id_rsa", state)
    assert "authorized_keys" in run("ls -a ~/.ssh", state)
    assert "backup.sh" in run("ls ~/app", state)
    assert "Permission denied" in run("cat /etc/shadow", state)


def test_cron_points_at_the_planted_backup_script():
    state = ShellState(user="deploy")
    cron = run("crontab -l", state)
    assert "/home/deploy/app/backup.sh" in cron
    assert load_fs().is_file("/home/deploy/app/backup.sh")


def test_id_rsa_and_ssh_key_token_match():
    assert _value("ht-sshkey-001") == load_fs().files["/home/deploy/.ssh/id_rsa"]


def test_config_yaml_carries_the_db_and_redis_tokens():
    config = yaml.safe_load(load_fs().files["/home/deploy/app/config.yaml"])
    assert config["database"]["password"] == _value("ht-db-001")
    assert config["redis"]["password"] == _value("ht-redis-001")


def test_auth_log_matches_hostname_and_users():
    fs = load_fs()
    log = fs.files["/var/log/auth.log"]
    assert log.count(fs.hostname) >= 5
    assert "for deploy" in log
    assert "deploy:x:1001:1001" in fs.files["/etc/passwd"]
    # The shell banner says the last login was Thu Oct 8 18:22:41 from 10.20.0.5.
    assert "Oct  8 18:22:41 veltrix-app-01 sshd[1421]: Accepted password for deploy" in log
    assert "from 10.20.0.5" in log
    assert "Last login: Thu Oct  8 18:22:41 2026 from 10.20.0.5" in BANNER


def test_cpuinfo_lists_four_plausible_x86_cores():
    cpuinfo = load_fs().files["/proc/cpuinfo"]
    assert cpuinfo.count("processor\t:") == 4
    assert "GenuineIntel" in cpuinfo
    assert "model name\t: Intel(R) Xeon(R)" in cpuinfo
    assert "processor\t: 3" in cpuinfo


def test_os_release_still_ubuntu_22_04_4():
    assert 'PRETTY_NAME="Ubuntu 22.04.4 LTS"' in load_fs().files["/etc/os-release"]


def test_web_templates_exist_and_carry_the_right_content():
    names = (
        "phpmyadmin_login.html",
        "robots.txt",
        "directory_index.html",
        "git_config.txt",
        "git_head.txt",
        "forbidden_403.html",
    )
    for name in names:
        assert (TEMPLATES / name).read_text(encoding="utf-8").strip(), name

    login = (TEMPLATES / "phpmyadmin_login.html").read_text(encoding="utf-8")
    assert 'name="pma_password"' in login and "phpMyAdmin" in login

    assert "Disallow: /server-status" in (TEMPLATES / "robots.txt").read_text(encoding="utf-8")

    git_config = (TEMPLATES / "git_config.txt").read_text(encoding="utf-8")
    assert _value("ht-git-001") in git_config
    assert "decoy" in _value("ht-git-001").lower()
    assert (TEMPLATES / "git_head.txt").read_text(encoding="utf-8").startswith("ref: refs/heads/")

    assert "403 Forbidden" in (TEMPLATES / "forbidden_403.html").read_text(encoding="utf-8")
