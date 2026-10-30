from types import SimpleNamespace

import pytest

import ssh_client
from command_policy import CommandNotAllowed
from ssh_client import KaliSSHClient


def _configure_environment(monkeypatch):
    values = {
        "JUAN_VM_NAME": "kali-lab",
        "JUAN_VM_IP": "192.168.56.20",
        "JUAN_VM_USER": "student",
        "JUAN_VM_PASSWORD": "test-only-password",  # pragma: allowlist secret
        "ANGEL_VM_NAME": "kali-backup",
        "ANGEL_VM_IP": "192.168.56.21",
        "ANGEL_VM_USER": "student",
        "ANGEL_VM_PASSWORD": "test-only-password",  # pragma: allowlist secret
        "VBOXMANAGE_PATH": "VBoxManage",
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)


def test_running_vm_is_not_started_again(monkeypatch):
    _configure_environment(monkeypatch)
    calls = []

    def fake_run(command, **_kwargs):
        calls.append(command)
        return SimpleNamespace(stdout='VMState="running"\n', stderr="")

    monkeypatch.setattr(ssh_client.subprocess, "run", fake_run)
    client = KaliSSHClient()

    client.encender_si_apagada(client.maquinas[0])

    assert len(calls) == 1
    assert calls[0][1] == "showvminfo"


def test_remote_command_is_rejected_before_ssh_execution(monkeypatch):
    _configure_environment(monkeypatch)
    client = KaliSSHClient()
    client.cliente = object()
    client.maquina_activa = client.maquinas[0]

    with pytest.raises(CommandNotAllowed):
        client.ejecutar_sudo("rm -rf /tmp/example")


def test_command_timeout_must_stay_bounded(monkeypatch):
    _configure_environment(monkeypatch)
    monkeypatch.setenv("SSH_COMMAND_TIMEOUT_SECONDS", "600")
    client = KaliSSHClient()
    client.cliente = object()
    client.maquina_activa = client.maquinas[0]

    with pytest.raises(ValueError, match="between 1 and 120"):
        client.ejecutar_sudo("dig localhost A")

