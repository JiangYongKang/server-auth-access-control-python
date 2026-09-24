"""从 JSON 配置装配 AuthService（供独立进程/重启场景使用）。"""
from __future__ import annotations

import json
from pathlib import Path

from app.auth.models import AuthConfig
from app.auth.rate_limit import RateLimiter
from app.auth.service import AuthService
from app.auth.store import JsonStore


def load_config(cfg_path: str) -> AuthConfig:
    data = json.loads(Path(cfg_path).read_text(encoding="utf-8"))
    return AuthConfig(**data)


def load_service(cfg_path: str) -> AuthService:
    cfg = load_config(cfg_path)
    store = JsonStore(cfg.db_path)
    service = AuthService(cfg, store, RateLimiter(store))
    return service
