"""Provider factory: build a provider from a name and the environment."""

from __future__ import annotations

import os

from codejury.providers.anthropic import AnthropicProvider
from codejury.providers.base import Provider
from codejury.providers.litellm import LiteLLMProvider
from codejury.providers.openai import OpenAIProvider
from codejury.providers.retry import RetryProvider

PROVIDERS = ("anthropic", "openai", "litellm")
# the default provider, env-backed like the model and the checker provider, so the main
# backend can be set once in the environment instead of named on every invocation
DEFAULT_PROVIDER = os.environ.get("CODEJURY_PROVIDER", "anthropic")
DEFAULT_MODEL = os.environ.get("CODEJURY_MODEL", "claude-opus-4-8")
DEFAULT_API_KEY = os.environ.get("CODEJURY_API_KEY")
DEFAULT_API_BASE = os.environ.get("CODEJURY_API_BASE")
# retry attempts on a transient failure, env-backed like the rest of the backend config so
# CI can set it once, symmetric with the env-only timeout knobs
DEFAULT_RETRIES = int(os.environ.get("CODEJURY_RETRIES", "2"))

# Per-role model backends, finder, challenger, and judge, shared by both review paths. A role
# names what a model does, finder scans, challenger refutes, judge confirms before a deletion,
# so a different vendor in any seat gives uncorrelated blind spots. Each field defaults to None
# meaning inherit the base backend, resolved at build time, so the common single-model run sets
# only --model. A distinct judge from the challenger is what lets a deletion need two models to
# agree, with none set nothing is refuted, the recall-safe default.
ROLES = ("finder", "challenger", "judge")
DEFAULT_ROLE_BACKENDS = {
    role: {
        "provider": os.environ.get(f"CODEJURY_{role.upper()}_PROVIDER"),
        "model": os.environ.get(f"CODEJURY_{role.upper()}_MODEL"),
        "api_key": os.environ.get(f"CODEJURY_{role.upper()}_API_KEY"),
        "api_base": os.environ.get(f"CODEJURY_{role.upper()}_API_BASE"),
        "wire_api": os.environ.get(f"CODEJURY_{role.upper()}_WIRE_API"),
    }
    for role in ROLES
}
# A single per-call deadline in seconds. The provider SDK enforces it, and when retries are on
# the retry layer enforces the same bound with a daemon thread, for the case the SDK timeout
# cannot cover such as a proxy that holds the connection open.
DEFAULT_TIMEOUT = float(os.environ.get("CODEJURY_TIMEOUT", "240"))


def make_provider(
    name: str, *, api_key: str | None = None, api_base: str | None = None, retries: int = 0,
    wire_api: str = "chat", timeout: float = DEFAULT_TIMEOUT
) -> Provider:
    if name == "openai":
        provider: Provider = OpenAIProvider(api_key=api_key, api_base=api_base, wire_api=wire_api, timeout=timeout)
    elif name == "litellm":
        provider = LiteLLMProvider(api_key=api_key, api_base=api_base, timeout=timeout)
    else:
        provider = AnthropicProvider(api_key=api_key, api_base=api_base, timeout=timeout)
    if retries > 0:
        provider = RetryProvider(provider, max_attempts=retries + 1, hard_timeout=timeout)
    return provider
