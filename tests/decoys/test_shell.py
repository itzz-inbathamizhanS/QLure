from decoys import honeytokens
from decoys.ssh.shell import ShellState, run


def test_fake_shell_answers_from_the_table_only():
    state = ShellState(user="deploy")
    assert run("whoami", state) == "deploy\n"
    assert run("uname -a", state).startswith("Linux veltrix-app-01")
    assert run("rm -rf /", state) == "bash: rm: command not found\n"
    assert run("wget http://example.com/x", state).startswith("wget: unable to resolve")
    assert run("sudo su", state).endswith("This incident will be reported.\n")


def test_cd_and_ls_follow_the_fake_tree():
    state = ShellState(user="deploy")
    assert run("ls", state) == ".bash_history\napp\nnotes.txt\n"
    assert run("cd app", state) == ""
    assert run("pwd", state) == "/home/deploy/app\n"
    assert "No such file" in run("cd /nowhere", state)
    assert run("cat README.md", state).startswith("# veltrix-dispatch")


def test_history_file_holds_the_api_key_and_no_real_secret():
    state = ShellState(user="deploy")
    history = run("cat ~/.bash_history", state)
    assert honeytokens.get("ht-api-001")["value"] in history
    assert "{{" not in history
