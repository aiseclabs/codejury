from types import SimpleNamespace

from codejury.providers.base import Message
from codejury.providers.litellm import LiteLLMProvider


def _fake(reply="ok", model="gpt-x"):
    captured = {}

    def completion(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=reply))], model=model)

    return completion, captured


def test_prepends_system_and_maps_messages():
    completion, captured = _fake()
    provider = LiteLLMProvider(completion=completion)
    result = provider.complete(
        system="sys",
        messages=[Message(role="user", content="hi"), Message(role="assistant", content="prev")],
        model="gpt-4o",
        max_tokens=128,
    )
    assert result.text == "ok"
    assert captured["messages"] == [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": "prev"},
    ]
    assert captured["max_tokens"] == 128


def test_omits_system_message_when_empty():
    completion, captured = _fake()
    LiteLLMProvider(completion=completion).complete(
        system="", messages=[Message(role="user", content="x")], model="m", max_tokens=8
    )
    assert captured["messages"] == [{"role": "user", "content": "x"}]


def test_passes_api_key_and_base_only_when_set():
    completion, captured = _fake()
    LiteLLMProvider(completion=completion, api_key="k", api_base="http://proxy").complete(
        system="s", messages=[Message(role="user", content="x")], model="m", max_tokens=8
    )
    assert captured["api_key"] == "k"
    assert captured["api_base"] == "http://proxy"

    completion2, captured2 = _fake()
    LiteLLMProvider(completion=completion2).complete(
        system="s", messages=[Message(role="user", content="x")], model="m", max_tokens=8
    )
    assert "api_key" not in captured2
    assert "api_base" not in captured2


def test_extracts_text_from_content_block_list():
    def completion(**kwargs):
        return SimpleNamespace(
            choices=[SimpleNamespace(message={"content": [{"text": "a"}, {"text": "b"}]})], model="m"
        )

    result = LiteLLMProvider(completion=completion).complete(
        system="s", messages=[Message(role="user", content="x")], model="m", max_tokens=8
    )
    assert result.text == "ab"
