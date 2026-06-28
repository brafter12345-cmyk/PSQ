"""Secrets provider (WS10 / SCALE-14).

Today secrets are read straight from ``os.environ`` scattered across modules. This
puts them behind one interface so a vault (Doppler / HashiCorp Vault / cloud KMS)
can be swapped in with rotation, without touching call sites.

Backends (by ``SECRETS_BACKEND``):
  * ``env`` (default) — read from the process environment.
  * ``vault`` — read from HashiCorp Vault (hvac); cached with a TTL so rotation is
    picked up without a redeploy. Import-guarded (hvac optional).

Usage:  from secrets_provider import get_secret;  key = get_secret("HIBP_API_KEY")
"""
from __future__ import annotations

import os
import time
from typing import Optional


class EnvSecrets:
    def get(self, name: str) -> Optional[str]:
        return os.environ.get(name)


class VaultSecrets:
    """HashiCorp Vault KV v2, cached with TTL for rotation. Path defaults to
    ``secret/data/<VAULT_SECRET_MOUNT or scanner>``."""

    def __init__(self, ttl: float = 300.0):
        import hvac  # optional
        self._client = hvac.Client(url=os.environ["VAULT_ADDR"],
                                   token=os.environ.get("VAULT_TOKEN"))
        self._path = os.environ.get("VAULT_SECRET_PATH", "scanner")
        self._ttl = ttl
        self._cache: dict = {}
        self._fetched = 0.0

    def _load(self) -> dict:
        now = time.time()
        if now - self._fetched < self._ttl and self._cache:
            return self._cache
        resp = self._client.secrets.kv.v2.read_secret_version(path=self._path)
        self._cache = resp["data"]["data"]
        self._fetched = now
        return self._cache

    def get(self, name: str) -> Optional[str]:
        try:
            v = self._load().get(name)
        except Exception:
            v = None
        return v if v is not None else os.environ.get(name)  # env fallback


_provider = None


def _get_provider():
    global _provider
    if _provider is None:
        if os.environ.get("SECRETS_BACKEND") == "vault":
            try:
                _provider = VaultSecrets()
            except Exception:
                _provider = EnvSecrets()
        else:
            _provider = EnvSecrets()
    return _provider


def get_secret(name: str, default: Optional[str] = None) -> Optional[str]:
    val = _get_provider().get(name)
    return val if val is not None else default


def reset_for_tests(provider=None):
    global _provider
    _provider = provider
