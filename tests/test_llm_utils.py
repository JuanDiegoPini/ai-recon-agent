import pytest

from llm_utils import InvalidModelResponse, parse_json_object


def test_parses_plain_json_object():
    assert parse_json_object('{"action": "finish"}') == {"action": "finish"}


def test_parses_json_code_fence():
    assert parse_json_object('```json\n{"ok": true}\n```') == {"ok": True}


@pytest.mark.parametrize("value", [None, "", "[]", "not json", "```json\n{}"])
def test_rejects_invalid_model_responses(value):
    with pytest.raises(InvalidModelResponse):
        parse_json_object(value)

