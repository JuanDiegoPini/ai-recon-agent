import pytest

from agenteAnalisis import corto, objetivo, resumen_en_frases


def test_target_sanitizes_sensitive_query_parameters():
    result = objetivo("https://example.com/login?token=secret-value&lang=en#section")

    assert result["url"] == "https://example.com/login?lang=en"
    assert result["sanitizada"] is True


def test_target_rejects_embedded_credentials():
    with pytest.raises(ValueError, match="sin credenciales"):
        objetivo("https://user:password@example.com")  # pragma: allowlist secret


def test_secret_values_are_redacted_from_short_text():
    assert "secret-value" not in corto("token=secret-value")


def test_summary_drops_incomplete_sentence():
    summary, adjusted = resumen_en_frases("First complete sentence. Incomplete fragment")

    assert summary == "First complete sentence."
    assert adjusted is True

