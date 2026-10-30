"""Authorization boundaries for passive and active reconnaissance."""

from __future__ import annotations

import ipaddress
import os
import socket
from dataclasses import dataclass
from typing import Callable, Iterable
from urllib.parse import urlsplit


ACTIVE_ACKNOWLEDGEMENT = "I_HAVE_EXPLICIT_AUTHORIZATION"


class ScopeViolation(ValueError):
    """Raised when a target or operation is outside the authorized scope."""


def _default_resolver(host: str) -> list[str]:
    return list(
        dict.fromkeys(
            item[4][0]
            for item in socket.getaddrinfo(
                host,
                None,
                type=socket.SOCK_STREAM,
            )
        )
    )


@dataclass(frozen=True)
class ScopeDecision:
    host: str
    operation: str
    reason: str


class ScopePolicy:
    """Allow lab targets by default and explicit allowlisted targets otherwise."""

    def __init__(
        self,
        authorized_targets: Iterable[str] = (),
        active_acknowledgement: str = "",
        resolver: Callable[[str], list[str]] = _default_resolver,
    ) -> None:
        self.authorized_targets = {
            item.strip().lower().rstrip(".")
            for item in authorized_targets
            if item and item.strip()
        }
        self.active_acknowledgement = active_acknowledgement.strip()
        self.resolver = resolver

    @classmethod
    def from_environment(cls) -> "ScopePolicy":
        targets = os.getenv("RECON_AUTHORIZED_TARGETS", "").split(",")
        return cls(
            authorized_targets=targets,
            active_acknowledgement=os.getenv("RECON_ACTIVE_ACK", ""),
        )

    @staticmethod
    def _host(target: str) -> str:
        if not isinstance(target, str) or not target.strip():
            raise ScopeViolation("A non-empty target is required")
        parsed = urlsplit(
            target.strip()
            if "://" in target
            else f"https://{target.strip()}"
        )
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ScopeViolation("Only HTTP(S), IP, or domain targets are supported")
        if parsed.username or parsed.password:
            raise ScopeViolation("Credentials must not be included in targets")
        return parsed.hostname.lower().rstrip(".")

    def _matches_allowlist(self, host: str) -> bool:
        for entry in self.authorized_targets:
            if entry.startswith("*."):
                suffix = entry[1:]
                if host.endswith(suffix) and host != suffix.lstrip("."):
                    return True
            elif host == entry:
                return True
        return False

    def _is_lab_target(self, host: str) -> bool:
        if host == "localhost" or host.endswith(".localhost"):
            return True
        try:
            addresses = [ipaddress.ip_address(host)]
        except ValueError:
            try:
                addresses = [
                    ipaddress.ip_address(address)
                    for address in self.resolver(host)
                ]
            except (OSError, ValueError) as error:
                raise ScopeViolation(
                    f"The target could not be resolved safely: {type(error).__name__}"
                ) from error
        return bool(addresses) and all(not address.is_global for address in addresses)

    def authorize(self, target: str, operation: str) -> ScopeDecision:
        if operation not in {"passive", "active"}:
            raise ValueError("operation must be 'passive' or 'active'")
        host = self._host(target)
        allowed = self._matches_allowlist(host) or self._is_lab_target(host)
        if not allowed:
            raise ScopeViolation(
                "Target is outside the lab and RECON_AUTHORIZED_TARGETS allowlist"
            )
        if (
            operation == "active"
            and self.active_acknowledgement != ACTIVE_ACKNOWLEDGEMENT
        ):
            raise ScopeViolation(
                "Active reconnaissance requires RECON_ACTIVE_ACK="
                f"{ACTIVE_ACKNOWLEDGEMENT}"
            )
        reason = "explicit allowlist" if self._matches_allowlist(host) else "lab network"
        return ScopeDecision(host=host, operation=operation, reason=reason)

