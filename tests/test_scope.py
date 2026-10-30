import pytest

from scope import ACTIVE_ACKNOWLEDGEMENT, ScopePolicy, ScopeViolation


def test_private_lab_target_is_allowed_for_passive_osint():
    policy = ScopePolicy(resolver=lambda _host: ["192.168.56.20"])

    decision = policy.authorize("https://lab.local", "passive")

    assert decision.host == "lab.local"
    assert decision.reason == "lab network"


def test_public_target_is_rejected_when_not_allowlisted():
    policy = ScopePolicy(resolver=lambda _host: ["93.184.216.34"])

    with pytest.raises(ScopeViolation, match="outside"):
        policy.authorize("https://example.com", "passive")


def test_public_allowlist_supports_subdomains():
    policy = ScopePolicy(
        authorized_targets=["*.example.test"],
        resolver=lambda _host: ["93.184.216.34"],
    )

    decision = policy.authorize("https://app.example.test", "passive")

    assert decision.reason == "explicit allowlist"


def test_active_reconnaissance_requires_explicit_acknowledgement():
    policy = ScopePolicy(resolver=lambda _host: ["127.0.0.1"])

    with pytest.raises(ScopeViolation, match="RECON_ACTIVE_ACK"):
        policy.authorize("http://localhost:8080", "active")


def test_active_lab_reconnaissance_is_allowed_after_acknowledgement():
    policy = ScopePolicy(
        active_acknowledgement=ACTIVE_ACKNOWLEDGEMENT,
        resolver=lambda _host: ["127.0.0.1"],
    )

    decision = policy.authorize("http://localhost:8080", "active")

    assert decision.operation == "active"


def test_credentials_in_target_are_rejected():
    policy = ScopePolicy(resolver=lambda _host: ["127.0.0.1"])

    with pytest.raises(ScopeViolation, match="Credentials"):
        policy.authorize(
            "https://user:password@localhost",  # pragma: allowlist secret
            "passive",
        )

