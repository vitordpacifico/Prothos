import json
import time
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class CacheEntry:
    key:        str
    value:      Any
    created_at: float = field(default_factory=time.time)
    ttl:        float = 300.0

    @property
    def expired(self) -> bool:
        return time.time() - self.created_at > self.ttl

    def to_dict(self) -> dict:
        return {
            "key":        self.key,
            "value":      self.value,
            "created_at": self.created_at,
            "ttl":        self.ttl,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "CacheEntry":
        return cls(
            key=d["key"],
            value=d["value"],
            created_at=d["created_at"],
            ttl=d["ttl"],
        )


class Cache:
    
    def __init__(
        self,
        ttl:          float           = 300.0,
        max_size:     int             = 1000,
        persist_path: Optional[str]   = None,
    ):
        self.ttl          = ttl
        self.max_size     = max_size
        self.persist_path = Path(persist_path) if persist_path else None
        self._store:      dict[str, CacheEntry] = {}

    def _make_key(self, key: Any) -> str:
        if isinstance(key, str):
            return key
        return hashlib.md5(json.dumps(key, sort_keys=True).encode()).hexdigest()

    def get(self, key: Any) -> Optional[Any]:
        k     = self._make_key(key)
        entry = self._store.get(k)
        if entry is None:
            return None
        if entry.expired:
            del self._store[k]
            return None
        return entry.value

    def set(self, key: Any, value: Any, ttl: Optional[float] = None):
        if len(self._store) >= self.max_size:
            self._evict()
        k = self._make_key(key)
        self._store[k] = CacheEntry(
            key=k,
            value=value,
            ttl=ttl if ttl is not None else self.ttl,
        )

    def delete(self, key: Any):
        k = self._make_key(key)
        self._store.pop(k, None)

    def has(self, key: Any) -> bool:
        return self.get(key) is not None

    def clear(self):
        self._store.clear()

    def _evict(self):
        expired = [k for k, e in self._store.items() if e.expired]
        for k in expired:
            del self._store[k]

        if len(self._store) >= self.max_size:
            oldest = sorted(self._store.items(), key=lambda x: x[1].created_at)
            for k, _ in oldest[:len(oldest) // 4]:
                del self._store[k]

    def save(self):
        if not self.persist_path:
            return
        self.persist_path.parent.mkdir(parents=True, exist_ok=True)
        data = {k: e.to_dict() for k, e in self._store.items() if not e.expired}
        with open(self.persist_path, "w") as f:
            json.dump(data, f)

    def load(self):
        if not self.persist_path or not self.persist_path.exists():
            return
        try:
            with open(self.persist_path) as f:
                data = json.load(f)
            for k, d in data.items():
                entry = CacheEntry.from_dict(d)
                if not entry.expired:
                    self._store[k] = entry
        except Exception:
            pass

    @property
    def size(self) -> int:
        return len(self._store)

    @property
    def stats(self) -> dict:
        total   = len(self._store)
        expired = sum(1 for e in self._store.values() if e.expired)
        return {
            "total":   total,
            "active":  total - expired,
            "expired": expired,
            "max":     self.max_size,
        }


_global_cache: Optional[Cache] = None


def get_cache(
    ttl:          float         = 300.0,
    persist_path: Optional[str] = None,
) -> Cache:
    global _global_cache
    if _global_cache is None:
        _global_cache = Cache(ttl=ttl, persist_path=persist_path)
        if persist_path:
            _global_cache.load()
    return _global_cache