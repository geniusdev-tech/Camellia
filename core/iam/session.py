import time
from threading import Lock
from typing import Any


class KeyManager:
    def __init__(self) -> None:
        self._items: dict[str, tuple[Any, float | None]] = {}
        self._lock = Lock()

    def store_key(self, key_id: str | int, value: Any, ttl: int | None = None) -> None:
        expires_at = time.time() + ttl if ttl else None
        with self._lock:
            self._items[str(key_id)] = (value, expires_at)

    def get_key(self, key_id: str | int) -> Any:
        with self._lock:
            item = self._items.get(str(key_id))
            if not item:
                return None
            value, expires_at = item
            if expires_at and time.time() > expires_at:
                self._items.pop(str(key_id), None)
                return None
            return value

    def clear_key(self, key_id: str | int) -> None:
        with self._lock:
            self._items.pop(str(key_id), None)


key_manager = KeyManager()
