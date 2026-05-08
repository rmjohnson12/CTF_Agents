import sys
import types

from agents.specialists.forensics.forensics_agent import ForensicsAgent


class _FakeStream:
    def __init__(self, data: str = ""):
        self._data = data.encode()

    def read(self):
        return self._data


class _FakeSSHClient:
    instances = []

    def __init__(self):
        self.connected = None
        self.commands = []
        _FakeSSHClient.instances.append(self)

    def set_missing_host_key_policy(self, policy):
        self.policy = policy

    def connect(self, host, **kwargs):
        self.connected = (host, kwargs)

    def exec_command(self, command, timeout=None):
        self.commands.append(command)
        if "grep -RIsE" in command:
            return None, _FakeStream("HTB{live_ssh_rootkit_found}\n"), _FakeStream()
        return None, _FakeStream("/etc/ld.so.preload\n"), _FakeStream()

    def close(self):
        self.closed = True


class _BypassOnlySSHClient(_FakeSSHClient):
    def exec_command(self, command, timeout=None):
        self.commands.append(command)
        if "preload bypass search" in command:
            return None, _FakeStream("/var/pr3l04d_/flag.txt\nHTB{preload_bypass_found}\n"), _FakeStream()
        return None, _FakeStream("/etc/ld.so.preload\n/lib/x86_64-linux-gnu/libc.hook.so.6\n"), _FakeStream()


def _install_fake_paramiko(monkeypatch):
    _FakeSSHClient.instances = []
    fake = types.SimpleNamespace(
        SSHClient=_FakeSSHClient,
        AutoAddPolicy=lambda: object(),
    )
    monkeypatch.setitem(sys.modules, "paramiko", fake)


def test_extract_ssh_context_from_rootkit_prompt():
    challenge = {
        "description": (
            "Investigate userland rootkit. Creds: root:hackthebox "
            "xThe IP and port are 154.57.164.66:31361"
        )
    }

    assert ForensicsAgent._extract_ssh_context(challenge) == (
        "154.57.164.66",
        31361,
        "root",
        "hackthebox",
    )


def test_forensics_agent_solves_live_ssh_rootkit_when_flag_seen(monkeypatch):
    _install_fake_paramiko(monkeypatch)
    challenge = {
        "id": "live_rootkit",
        "category": "forensics",
        "description": (
            "SSH server has library linking errors and possible userland rootkit. "
            "Creds: root:hackthebox IP and port are 154.57.164.66:31361"
        ),
        "files": [],
    }

    result = ForensicsAgent().solve_challenge(challenge)

    assert result["status"] == "solved"
    assert result["flag"] == "HTB{live_ssh_rootkit_found}"
    assert result["artifacts"]["ssh_target"] == "154.57.164.66:31361"
    client = _FakeSSHClient.instances[0]
    assert client.connected[0] == "154.57.164.66"
    assert client.connected[1]["port"] == 31361
    assert client.connected[1]["username"] == "root"
    assert client.connected[1]["password"] == "hackthebox"
    assert any("/etc/ld.so.preload" in command for command in client.commands)


def test_live_ssh_preload_bypass_is_env_gated(monkeypatch):
    _FakeSSHClient.instances = []
    fake = types.SimpleNamespace(
        SSHClient=_BypassOnlySSHClient,
        AutoAddPolicy=lambda: object(),
    )
    monkeypatch.setitem(sys.modules, "paramiko", fake)
    monkeypatch.setenv("CTF_AGENTS_ALLOW_SSH_PRELOAD_BYPASS", "1")
    challenge = {
        "id": "live_rootkit_bypass",
        "category": "forensics",
        "description": (
            "SSH server has library linking errors and possible userland rootkit. "
            "Creds: root:hackthebox IP and port are 154.57.164.66:31361"
        ),
        "files": [],
    }

    result = ForensicsAgent().solve_challenge(challenge)

    assert result["status"] == "solved"
    assert result["flag"] == "HTB{preload_bypass_found}"
    assert any("preload bypass search" in command for command in _FakeSSHClient.instances[0].commands)
