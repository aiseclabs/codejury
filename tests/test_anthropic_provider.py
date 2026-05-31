from types import SimpleNamespace

from codejury.providers.anthropic import AnthropicProvider
from codejury.providers.base import Message


class _FakeClient:
    """Records the kwargs passed to messages.create and returns a canned reply."""

    def __init__(self):
        self.create_kwargs = {}
        self.messages = SimpleNamespace(create=self._create)

    def _create(self, **kwargs):
        self.create_kwargs = kwargs
        return SimpleNamespace(
            content=[SimpleNamespace(text="he"), SimpleNamespace(text="llo")],
            model="claude-real",
        )


def _provider():
    client = _FakeClient()
    return AnthropicProvider(client=client), client


def test_maps_messages_and_joins_text_blocks():
    provider, client = _provider()
    result = provider.complete(
        system="be careful",
        messages=[Message(role="user", content="hi")],
        model="claude-x",
        max_tokens=64,
    )
    assert result.text == "hello"  # content blocks joined
    assert client.create_kwargs["messages"] == [{"role": "user", "content": "hi"}]
    assert client.create_kwargs["max_tokens"] == 64


def test_no_cache_keeps_system_as_plain_string():
    provider, client = _provider()
    provider.complete(system="sys", messages=[Message(role="user", content="x")], model="m", max_tokens=8)
    assert client.create_kwargs["system"] == "sys"


def test_cache_marks_system_with_ephemeral_cache_control():
    provider, client = _provider()
    provider.complete(
        system="sys", messages=[Message(role="user", content="x")], model="m", max_tokens=8, cache=True
    )
    assert client.create_kwargs["system"] == [
        {"type": "text", "text": "sys", "cache_control": {"type": "ephemeral"}}
    ]
