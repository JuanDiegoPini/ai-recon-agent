import shlex

import pytest

from command_policy import CommandNotAllowed, validate_remote_command


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("nmap -sT -Pn -p 80 127.0.0.1", "nmap"),
        ("curl -sS --max-time 5 http://127.0.0.1", "curl"),
        ("whatweb -a 1 http://127.0.0.1", "whatweb"),
        ("timeout 12s dig +time=2 localhost A", "dig"),
    ],
)
def test_read_only_recon_commands_are_allowed(command, expected):
    assert validate_remote_command(command) == expected


def test_fixed_tls_pipeline_is_allowed():
    inner = (
        "timeout 12s openssl s_client -connect 127.0.0.1:443 "
        "-servername localhost </dev/null 2>/dev/null | "
        "openssl x509 -noout -subject -issuer -dates"
    )
    command = "bash -o pipefail -c " + shlex.quote(inner)

    assert validate_remote_command(command) == "openssl"


@pytest.mark.parametrize(
    "command",
    [
        "rm -rf /tmp/example",
        "curl http://localhost; whoami",
        "nmap 127.0.0.1 && id",
        "bash -lc 'id'",
        "curl http://localhost\nwhoami",
    ],
)
def test_unsafe_or_unrelated_commands_are_rejected(command):
    with pytest.raises(CommandNotAllowed):
        validate_remote_command(command)

