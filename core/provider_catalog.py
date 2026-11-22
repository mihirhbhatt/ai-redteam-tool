"""Load explicitly configured OpenAI-compatible provider profiles."""

from dataclasses import dataclass
from pathlib import Path
import re
from urllib.parse import urlsplit

import yaml


@dataclass(frozen=True)
class ProviderProfile:
    base_url: str
    api_key_env: str


def load_provider_catalog(path: str | Path) -> dict[str, ProviderProfile]:
    try:
        with Path(path).open(encoding="utf-8") as file:
            data = yaml.safe_load(file)
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"Cannot load provider catalog {path}: {exc}") from exc

    if not isinstance(data, dict) or set(data) != {"providers"}:
        raise ValueError("Provider catalog must contain only a providers mapping.")
    providers = data["providers"]
    if not isinstance(providers, dict):
        raise ValueError("Provider catalog providers must be a mapping.")

    result: dict[str, ProviderProfile] = {}
    for name, entry in providers.items():
        if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", name):
            raise ValueError("Provider names must use lowercase letters, digits, - or _.")
        if not isinstance(entry, dict) or set(entry) != {"base_url", "api_key_env"}:
            raise ValueError(f"Provider {name!r} must contain base_url and api_key_env only.")
        url = entry["base_url"]
        key_env = entry["api_key_env"]
        if not isinstance(url, str):
            raise ValueError(f"Provider {name!r} must have an HTTPS base_url.")
        try:
            parsed = urlsplit(url)
            port = parsed.port
        except ValueError as exc:
            raise ValueError(f"Provider {name!r} has an invalid base_url.") from exc
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or any(char.isspace() for char in url)
            or port == 0
        ):
            raise ValueError(f"Provider {name!r} must have an HTTPS base_url without credentials, query, or fragment.")
        if not isinstance(key_env, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key_env):
            raise ValueError(f"Provider {name!r} must have a valid api_key_env name.")
        result[name] = ProviderProfile(base_url=url.rstrip("/"), api_key_env=key_env)
    return result
