import asyncio
import random
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse
import httpx
from rich.console import Console

console = Console()


@dataclass
class ProxyEntry:
    url:           str
    alive:         bool  = True
    last_checked:  float = field(default_factory=time.time)
    fail_count:    int   = 0
    success_count: int   = 0
    response_time: float = 0.0

    @property
    def scheme(self) -> str:
        return urlparse(self.url).scheme

    @property
    def reliability(self) -> float:
        total = self.fail_count + self.success_count
        if total == 0:
            return 1.0
        return self.success_count / total

    def to_dict(self) -> dict:
        return self.__dict__.copy()


class ProxyManager:

    MAX_FAILS = 3

    def __init__(
        self,
        rotate:     bool  = True,
        check_url:  str   = "https://httpbin.org/ip",
        timeout:    float = 8.0,
    ):
        self.rotate    = rotate
        self.check_url = check_url
        self.timeout   = timeout
        self._proxies: list[ProxyEntry] = []
        self._index:   int              = 0

    @classmethod
    def from_list(cls, urls: list[str], **kwargs) -> "ProxyManager":
        pm = cls(**kwargs)
        for url in urls:
            pm.add(url)
        return pm

    @classmethod
    def from_file(cls, path: str, **kwargs) -> "ProxyManager":
        pm = cls(**kwargs)
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        pm.add(line)
        except Exception as e:
            console.print(f"[red][!] Failed to load proxy file: {e}[/red]")
        return pm

    def add(self, url: str):
        if not url.startswith(("http://", "https://", "socks5://", "socks4://")):
            url = f"http://{url}"
        if not any(p.url == url for p in self._proxies):
            self._proxies.append(ProxyEntry(url=url))

    def remove(self, url: str):
        self._proxies = [p for p in self._proxies if p.url != url]

    def _alive(self) -> list[ProxyEntry]:
        return [p for p in self._proxies if p.alive]

    def next(self) -> Optional[str]:
        alive = self._alive()
        if not alive:
            return None

        if self.rotate:
            proxy = random.choice(alive)
        else:
            proxy = alive[self._index % len(alive)]
            self._index += 1

        return proxy.url

    def best(self) -> Optional[str]:
        alive = self._alive()
        if not alive:
            return None
        return max(alive, key=lambda p: p.reliability).url

    def report_success(self, url: str, response_time: float = 0.0):
        for p in self._proxies:
            if p.url == url:
                p.success_count += 1
                p.response_time  = response_time
                p.fail_count     = max(0, p.fail_count - 1)
                p.alive          = True
                break

    def report_failure(self, url: str):
        for p in self._proxies:
            if p.url == url:
                p.fail_count += 1
                if p.fail_count >= self.MAX_FAILS:
                    p.alive = False
                    console.print(f"[dim][!] Proxy marked dead: {url}[/dim]")
                break

    async def check(self, url: str) -> bool:
        try:
            import time as _time
            t0 = _time.perf_counter()
            async with httpx.AsyncClient(
                proxy=url,
                verify=False,
                timeout=self.timeout,
            ) as client:
                r = await client.get(self.check_url)
                elapsed = round(_time.perf_counter() - t0, 3)
                if r.status_code == 200:
                    self.report_success(url, elapsed)
                    return True
        except Exception:
            self.report_failure(url)
        return False

    async def check_all(self):
        console.print(f"[dim]    Checking {len(self._proxies)} proxies...[/dim]")
        tasks   = [self.check(p.url) for p in self._proxies]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        alive   = sum(1 for r in results if r is True)
        console.print(f"[dim]    Alive: {alive}/{len(self._proxies)}[/dim]")

    def set_burp(self, host: str = "127.0.0.1", port: int = 8080):
        self.add(f"http://{host}:{port}")

    def set_tor(self, port: int = 9050):
        self.add(f"socks5://127.0.0.1:{port}")

    @property
    def count(self) -> int:
        return len(self._proxies)

    @property
    def alive_count(self) -> int:
        return len(self._alive())

    @property
    def stats(self) -> dict:
        return {
            "total":   self.count,
            "alive":   self.alive_count,
            "dead":    self.count - self.alive_count,
            "proxies": [p.to_dict() for p in self._proxies],
        }


_global_pm: Optional[ProxyManager] = None


def get_proxy_manager() -> ProxyManager:
    global _global_pm
    if _global_pm is None:
        _global_pm = ProxyManager()
    return _global_pm


def set_burp(host: str = "127.0.0.1", port: int = 8080) -> ProxyManager:
    pm = get_proxy_manager()
    pm.set_burp(host, port)
    return pm


def set_tor(port: int = 9050) -> ProxyManager:
    pm = get_proxy_manager()
    pm.set_tor(port)
    return pm