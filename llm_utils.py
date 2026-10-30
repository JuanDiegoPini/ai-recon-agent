"""Small, provider-independent helpers for structured LLM responses."""

from __future__ import annotations

import json


MAX_RESPONSE_CHARACTERS = 200_000


class InvalidModelResponse(ValueError):
    """Raised when a model response is empty, oversized, or not a JSON object."""


def parse_json_object(text: str | None) -> dict:
    if not isinstance(text, str) or not text.strip():
        raise InvalidModelResponse("The model returned an empty response")
    value = text.strip()
    if len(value) > MAX_RESPONSE_CHARACTERS:
        raise InvalidModelResponse("The model response is too large")
    if value.startswith("```"):
        lines = value.splitlines()
        if len(lines) < 3 or lines[-1].strip() != "```":
            raise InvalidModelResponse("The fenced JSON response is incomplete")
        value = "\n".join(lines[1:-1]).strip()
        if value.lower().startswith("json"):
            value = value[4:].lstrip()
    try:
        result = json.loads(value)
    except json.JSONDecodeError as error:
        raise InvalidModelResponse(
            f"The model did not return valid JSON: line {error.lineno}, column {error.colno}"
        ) from error
    if not isinstance(result, dict):
        raise InvalidModelResponse("The model response must be a JSON object")
    return result

