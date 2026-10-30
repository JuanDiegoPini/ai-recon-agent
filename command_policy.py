"""Validation for the small set of commands executed in the Kali lab VM."""

from __future__ import annotations

import shlex


class CommandNotAllowed(ValueError):
    """Raised when a remote command is outside the read-only tool policy."""


DIRECT_TOOLS = {"nmap", "curl", "whatweb", "dig"}
FORBIDDEN_SHELL_TOKENS = (";", "&&", "||", "`", "$(", ">", "<")


def validate_remote_command(command: str) -> str:
    """Return the executable name when a generated command is permitted."""
    if not isinstance(command, str) or not command.strip():
        raise CommandNotAllowed("Remote command must be a non-empty string")
    if "\n" in command or "\r" in command:
        raise CommandNotAllowed("Multiline remote commands are not allowed")

    tokens = shlex.split(command, posix=True)
    if not tokens:
        raise CommandNotAllowed("Remote command is empty")
    executable = tokens[0]

    if executable in DIRECT_TOOLS:
        if any(token in command for token in FORBIDDEN_SHELL_TOKENS):
            raise CommandNotAllowed("Shell control operators are not allowed")
        return executable

    if executable == "timeout" and len(tokens) >= 3 and tokens[2] == "dig":
        if any(token in command for token in FORBIDDEN_SHELL_TOKENS):
            raise CommandNotAllowed("Shell control operators are not allowed")
        return "dig"

    if executable == "bash" and len(tokens) == 5:
        expected_prefix = ["bash", "-o", "pipefail", "-c"]
        inner = tokens[4]
        if tokens[:4] != expected_prefix:
            raise CommandNotAllowed("Only the fixed TLS pipeline may use bash")
        if not inner.startswith("timeout 12s openssl s_client "):
            raise CommandNotAllowed("Unexpected TLS pipeline")
        if "| openssl x509 -noout -subject -issuer -dates" not in inner:
            raise CommandNotAllowed("Unexpected TLS certificate parser")
        if any(token in inner for token in (";", "&&", "||", "`", "$(")):
            raise CommandNotAllowed("Unsafe shell control operator")
        return "openssl"

    raise CommandNotAllowed(f"Executable is not allowed: {executable}")

