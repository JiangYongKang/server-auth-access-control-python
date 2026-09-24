"""跨进程并发：两个独立进程同时刷新同一令牌，只有一个成功。"""
from __future__ import annotations

import json
import logging
import multiprocessing as mp
from pathlib import Path

from tests.conftest import T0

logger = logging.getLogger("test.multiprocess")


def _refresh_in_subprocess(cfg_path: str, refresh_token: str, out_path: str, barrier):
    from app.auth.config_loader import load_service

    svc = load_service(cfg_path)
    # 两个进程在此对齐，随后才同时尝试抢同一 family 的跨进程文件锁
    barrier.wait()
    try:
        svc.refresh(refresh_token, now=T0 + 1)
        result = {"ok": True}
    except Exception as exc:  # noqa: BLE001
        code = exc.error_code
        result = {"ok": False, "error": code.value if hasattr(code, "value") else str(code)}
    Path(out_path).write_text(json.dumps(result))


def test_two_processes_refresh_same_token(tmp_path):
    from app.auth.rate_limit import RateLimiter
    from app.auth.service import AuthService
    from app.auth.store import JsonStore
    from tests.conftest import make_config

    cfg = make_config(tmp_path)
    cfg_path = str(tmp_path / "cfg.json")
    Path(cfg_path).write_text(json.dumps({"db_path": cfg.db_path, "secret": cfg.secret,
                                          "access_token_ttl_seconds": cfg.access_token_ttl_seconds,
                                          "refresh_token_ttl_seconds": cfg.refresh_token_ttl_seconds,
                                          "login_max_failures": cfg.login_max_failures,
                                          "login_lock_seconds": cfg.login_lock_seconds,
                                          "refresh_max_failures": cfg.refresh_max_failures,
                                          "refresh_lock_seconds": cfg.refresh_lock_seconds,
                                          "access_max_failures": cfg.access_max_failures,
                                          "access_lock_seconds": cfg.access_lock_seconds,
                                          "failure_window_seconds": cfg.failure_window_seconds}))
    store = JsonStore(cfg.db_path)
    svc = AuthService(cfg, store, RateLimiter(store))
    svc.ensure_seed_users()
    tokens = svc.login("alice", "alice-password", now=T0)

    ctx = mp.get_context("spawn")
    barrier = ctx.Barrier(2)
    outs = [str(tmp_path / f"out{i}.json") for i in range(2)]
    procs = [
        ctx.Process(target=_refresh_in_subprocess,
                    args=(cfg_path, tokens.refresh_token, outs[i], barrier))
        for i in range(2)
    ]
    for p in procs:
        p.start()
    for p in procs:
        p.join()

    results = [json.loads(Path(o).read_text()) for o in outs]
    logger.info("input: 2 processes refresh same token; results=%s", results)
    successes = [r for r in results if r["ok"]]
    failures = [r for r in results if not r["ok"]]
    assert len(successes) == 1, results
    assert len(failures) == 1
    assert failures[0]["error"] == "refresh_concurrent"
