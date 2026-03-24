import asyncio
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse


@dataclass
class RateLimitEntry:
    domain:       str
    last_request: float = field(default_factory=time.perf_counter)
    request_count: int  = 0
    blocked_until: float = 0.0

    @property
    def is_blocked(self) -> bool:
        return time.perf_counter() < self.blocked_until


class RateLimiter:

    def __init__(
        self,
        delay:          float = 0.0,
        max_per_second: float = 0.0,
        backoff_factor: float = 2.0,
        max_backoff:    float = 60.0,
    ):
        self.delay          = delay
        self.min_interval   = 1.0 / max_per_second if max_per_second > 0 else delay
        self.backoff_factor = backoff_factor
        self.max_backoff    = max_backoff
        self._domains:      dict[str, RateLimitEntry] = {}
        self._lock          = asyncio.Lock()

    def _get_domain(self, url: str) -> str:
        try:
            return urlparse(url).netloc or url
        except Exception:
            return url

    def _get_entry(self, domain: str) -> RateLimitEntry:
        if domain not in self._domains:
            self._domains[domain] = RateLimitEntry(domain=domain)
        return self._domains[domain]

    async def acquire(self, url: str):
        domain = self._get_domain(url)

        async with self._lock:
            entry = self._get_entry(domain)

            if entry.is_blocked:
                wait = entry.blocked_until - time.perf_counter()
                if wait > 0:
                    await asyncio.sleep(wait)

            interval = self.min_interval
            elapsed  = time.perf_counter() - entry.last_request

            if elapsed < interval:
                await asyncio.sleep(interval - elapsed)

            entry.last_request  = time.perf_counter()
            entry.request_count += 1

    def report_blocked(self, url: str, retry_after: Optional[float] = None):
        domain = self._get_domain(url)
        entry  = self._get_entry(domain)

        if retry_after:
            backoff = min(retry_after, self.max_backoff)
        else:
            backoff = min(
                self.min_interval * (self.backoff_factor ** entry.request_count),
                self.max_backoff,
            )

        entry.blocked_until = time.perf_counter() + backoff

    def is_blocked(self, url: str) -> bool:
        domain = self._get_domain(url)
        entry  = self._domains.get(domain)
        return entry.is_blocked if entry else False

    def reset(self, url: str):
        domain = self._get_domain(url)
        self._domains.pop(domain, None)

    def clear(self):
        self._domains.clear()

    @property
    def stats(self) -> dict:
        return {
            "domains":  len(self._domains),
            "blocked":  sum(1 for e in self._domains.values() if e.is_blocked),
            "requests": sum(e.request_count for e in self._domains.values()),
        }


_global_limiter: Optional[RateLimiter] = None


def get_rate_limiter(
    delay:          float = 0.0,
    max_per_second: float = 0.0,
) -> RateLimiter:
    global _global_limiter
    if _global_limiter is None:
        _global_limiter = RateLimiter(
            delay=delay,
            max_per_second=max_per_second,
        )
    return _global_limiter