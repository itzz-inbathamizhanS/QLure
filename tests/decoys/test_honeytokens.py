import re
from pathlib import Path

from decoys import honeytokens

DECOYS = Path(__file__).resolve().parents[2] / "decoys"
FORBIDDEN = re.compile(r"\b(exec|eval|subprocess|os\.system|popen)\(")


def test_every_honeytoken_is_marked_as_a_decoy_value():
    for token in honeytokens.load().values():
        assert "decoy" in token["value"].lower(), token["id"]


def test_honeytoken_ids_are_unique_and_known_to_the_decoys():
    tokens = honeytokens.load()
    assert len(tokens) == len({t["id"] for t in tokens.values()})
    assert {"ht-aws-001", "ht-db-001", "ht-ssh-001", "ht-api-001"} <= set(tokens)


def test_ssh_password_only_matches_its_username():
    value = honeytokens.get("ht-ssh-001")["value"]
    assert honeytokens.find("ssh_password", value, "deploy")["id"] == "ht-ssh-001"
    assert honeytokens.find("ssh_password", value, "root") is None


def test_decoys_never_execute_anything():
    for path in DECOYS.rglob("*.py"):
        assert not FORBIDDEN.search(path.read_text()), path
