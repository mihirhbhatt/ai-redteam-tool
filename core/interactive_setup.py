"""Interactive selection of target and judge without storing credentials."""

import os
from typing import Any

from core.provider_catalog import load_provider_catalog


def _choice(prompt: str, valid: set[str]) -> str:
    while True:
        value = input(prompt).strip().lower()
        if value in valid:
            return value
        print(f"Choose one of: {', '.join(sorted(valid))}.")


def _model() -> str:
    while True:
        model = input("Model ID: ").strip()
        if model:
            return model
        print("A model ID is required.")


def _api_config(catalog_path: str) -> dict[str, str | None]:
    profiles = load_provider_catalog(catalog_path)
    if "anthropic" in profiles:
        raise ValueError("Catalog profile 'anthropic' conflicts with the native Anthropic adapter.")
    print("OpenAI-compatible API profiles:")
    for name in sorted(profiles):
        profile = profiles[name]
        print(f"  {name}: {profile.base_url} (key: {profile.api_key_env})")
    print("  anthropic: Anthropic API (key: ANTHROPIC_API_KEY)")
    name = _choice("Provider profile: ", set(profiles) | {"anthropic"})
    model = _model()
    if name == "anthropic":
        provider, base_url, key_env = "anthropic", None, "ANTHROPIC_API_KEY"
    else:
        profile = profiles[name]
        provider, base_url, key_env = "openai", profile.base_url, profile.api_key_env
    if not os.getenv(key_env):
        raise ValueError(
            f"API key environment variable {key_env!r} is not set. "
            "Set it in PowerShell before starting this command."
        )
    return {"provider": provider, "model": model, "base_url": base_url, "api_key_env": key_env}


def _local_config() -> dict[str, str | None]:
    print("Enter an installed Ollama model name (see: ollama list).")
    return {
        "provider": "ollama",
        "model": _model(),
        "base_url": "http://localhost:11434",
        "api_key_env": None,
    }


def configure_interactively(
    config: dict[str, Any],
    catalog_path: str,
    *,
    no_judge: bool = False,
    check_target: bool = False,
) -> None:
    """Update an in-memory configuration using explicit operator choices."""
    print("Select a model target:")
    print("  1. Local Ollama (localhost, no API key)")
    print("  2. Hosted API")
    mode = _choice("Choice [1/2]: ", {"1", "2"})
    target = config["target"]
    target.update(_local_config() if mode == "1" else _api_config(catalog_path))
    if check_target:
        return

    judge = config.setdefault("judge", {})
    if no_judge:
        judge["enabled"] = False
        print("LLM judge disabled; rule-based evaluation will be used.")
        return

    while True:
        print("Select an independent evaluation method:")
        print("  1. Rule-based evaluation (no LLM judge)")
        print("  2. Local Ollama judge")
        print("  3. Hosted API judge")
        selection = _choice("Choice [1/2/3]: ", {"1", "2", "3"})
        if selection == "1":
            judge["enabled"] = False
            print("LLM judge disabled; rule-based evaluation will be used.")
            return
        if selection == "2":
            judge.update(_local_config())
        else:
            print(
                "A hosted judge receives test prompts, target responses, and "
                "possibly system instructions, and may incur charges."
            )
            if _choice("Allow sending this data to a hosted judge? [y/n]: ", {"y", "n"}) == "n":
                continue
            judge.update(_api_config(catalog_path))
        judge["enabled"] = True
        print(f"LLM judge selected: {judge['provider']} / {judge['model']}")
        return
