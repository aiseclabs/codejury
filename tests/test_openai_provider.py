from types import SimpleNamespace

from codejury.providers.base import Message
from codejury.providers.openai import OpenAIProvider


class _FakeClient:
    def __init__(self, reply="ok", model="gpt-4o"):
        self.create_kwargs = {}
        self._reply = reply
        self._model = model
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.create_kwargs = kwargs
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=self._reply))], model=self._model
        )


def test_prepends_system_and_maps_messages():
    client = _FakeClient(reply="hello", model="gpt-4o-mini")
    result = OpenAIProvider(client=client).complete(
        system="be careful",
        messages=[Message(role="user", content="hi")],
        model="gpt-4o",
        max_tokens=64,
    )
    assert result.text == "hello"
    assert client.create_kwargs["messages"] == [
        {"role": "system", "content": "be careful"},
        {"role": "user", "content": "hi"},
    ]
    assert client.create_kwargs["max_tokens"] == 64


def test_omits_system_message_when_empty():
    client = _FakeClient()
    OpenAIProvider(client=client).complete(
        system="", messages=[Message(role="user", content="x")], model="m", max_tokens=8
    )
    assert client.create_kwargs["messages"] == [{"role": "user", "content": "x"}]
