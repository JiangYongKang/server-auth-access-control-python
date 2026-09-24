"""基于 JSON 文件的持久化存储，进程重启后状态依然成立。

- load 时若文件不存在则从空库开始；
- save 使用 write-then-fsync-then-rename 原子替换，避免半写文件；
- 上下文管理器在进入时加锁、退出时（仅当无异常）落盘，
  保证“判定 + 状态变更”在进程内对同一存储串行化。
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from app.auth.models import Database


class JsonStore:
    def __init__(self, db_path: str) -> None:
        self.db_path = Path(db_path)
        self._lock = threading.RLock()
        self.db = self.load()

    def load(self) -> Database:
        if not self.db_path.exists():
            return Database.empty()
        with self.db_path.open("r", encoding="utf-8") as fh:
            payload = json.load(fh)
        return Database.from_json(payload)

    def save(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile_mkstemp_in_dir(self.db_path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self.db.to_json(), fh, ensure_ascii=False, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_name, self.db_path)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass
            raise

    def __enter__(self) -> Database:
        self._lock.acquire()
        # 进入临界区时重新读盘，保证在“新进程”或外部改写后视图最新
        if self.db_path.exists():
            self.db = self.load()
        return self.db

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            # 认证业务失败（凭据错误、重放吊销、频次锁定等）同样必须落盘：
            # 只要不是存储层自身的系统异常，退出临界区时都持久化。
            if exc is None or not isinstance(exc, (MemoryError, KeyboardInterrupt, SystemExit)):
                self.save()
        finally:
            self._lock.release()


def tempfile_mkstemp_in_dir(directory: Path) -> tuple[int, str]:
    import tempfile

    return tempfile.mkstemp(prefix=".auth_store.", suffix=".tmp", dir=str(directory))
