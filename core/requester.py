import asyncio
import time
import random
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Any
from urllib.parse import urlparse
import httpx
from rich.console import Console

console = Console()

@dataclass
class Response:
    url:           str
    status:        int
    text:          str
    headers:       dict
    elapsed:       float
    method:        str          = "GET"
    redirect_url:  Optional[str]= None
    error:         Optional[str]= None
    timestamp:     str          = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def ok(self) -> bool:
        return self.error is None and self.status < 400

    @property
    def is_redirect(self) -> bool:
        return self.status in (301, 302, 307, 308)

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "")

    @property
    def is_html(self) -> bool:
        return "html" in self.content_type

    @property
    def is_json(self) -> bool:
        return "json" in self.content_type

    def json(self) -> Any:
        import json
        try:
            return json.loads(self.text)
        except Exception:
            return None

    def to_dict(self) -> dict:
        return self.__dict__.copy()

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) "
    "Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
]

class Requester:

    def __init__(
        self,
        timeout:        int            = 10,
        retries:        int            = 2,
        concurrency:    int            = 50,
        delay:          float          = 0.0,
        rotate_ua:      bool           = False,
        proxy:          Optional[str]  = None,
        headers:        dict           = None,
        cookies:        dict           = None,
        follow_redirects: bool         = False,
        verify_ssl:     bool           = False,
        verbose:        bool           = False,
    ):
        self.timeout          = timeout
        self.retries          = retries
        self.delay            = delay
        self.rotate_ua        = rotate_ua
        self.proxy            = proxy
        self.extra_headers    = headers or {}
        self.extra_cookies    = cookies or {}
        self.follow_redirects = follow_redirects
        self.verify_ssl       = verify_ssl
        self.verbose          = verbose
        self.semaphore        = asyncio.Semaphore(concurrency)
        self.history:         list[Response] = []
        self._client:         Optional[httpx.AsyncClient] = None
        self._rate_limits:    dict[str, float] = {}

    async def __aenter__(self) -> "Requester":
        await self.start()
        return self

    async def __aexit__(self, *_):
        await self.close()

    async def start(self):

        self._client = httpx.AsyncClient(
            verify=self.verify_ssl,
            follow_redirects=self.follow_redirects,
            timeout=httpx.Timeout(self.timeout),
            proxy=self.proxy,
            cookies=self.extra_cookies,
            headers={
                "User-Agent": USER_AGENTS[0],
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                **self.extra_headers,
            },
        )

    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None

    async def _rate_limit(self, url: str):
        if self.delay <= 0:
            return
        domain   = urlparse(url).netloc
        last     = self._rate_limits.get(domain, 0)
        elapsed  = time.perf_counter() - last
        if elapsed < self.delay:
            await asyncio.sleep(self.delay - elapsed)
        self._rate_limits[domain] = time.perf_counter()

    async def request(
        self,
        method:   str,
        url:      str,
        *,
        params:   dict          = None,
        data:     dict          = None,
        json:     dict          = None,
        headers:  dict          = None,
        retries:  Optional[int] = None,
        **kwargs,
    ) -> Response:

        if not self._client:
            await self.start()

        # --- scope guard (safety rail) --------------------------------------
        try:
            from core.scope import get_guard, ScopeViolation
            from core import audit
            try:
                get_guard().assert_in_scope(url)
            except ScopeViolation as sv:
                audit.audit("scope_block", module="requester", target=url,
                            result=str(sv), severity="info")
                blocked = Response(
                    url=url, status=0, text="", headers={},
                    elapsed=0.0, method=method.upper(),
                    error=f"scope: {sv}",
                )
                self.history.append(blocked)
                return blocked
        except ImportError:
            pass

        max_retries = retries if retries is not None else self.retries
        last_error  = ""

        req_headers = headers or {}
        if self.rotate_ua:
            req_headers = {"User-Agent": random.choice(USER_AGENTS), **req_headers}

        async with self.semaphore:
            for attempt in range(max_retries + 1):

                await self._rate_limit(url)

                try:
                    t0   = time.perf_counter()
                    resp = await self._client.request(
                        method, url,
                        params=params,
                        data=data,
                        json=json,
                        headers=req_headers,
                        **kwargs,
                    )
                    elapsed = round(time.perf_counter() - t0, 3)

                    try:
                        text = resp.text
                    except Exception:
                        text = resp.content.decode("utf-8", errors="replace")

                    response = Response(
                        url=str(resp.url),
                        status=resp.status_code,
                        text=text,
                        headers={k.lower(): v for k, v in resp.headers.items()},
                        elapsed=elapsed,
                        method=method.upper(),
                        redirect_url=resp.headers.get("location"),
                    )

                    if self.verbose:
                        color = "green" if response.ok else "yellow"
                        console.print(
                            f"[dim]{method.upper()}[/dim] "
                            f"[{color}]{resp.status_code}[/{color}] "
                            f"[white]{url}[/white] "
                            f"[dim]{elapsed}s[/dim]"
                        )

                    self.history.append(response)
                    return response

                except httpx.TimeoutException:
                    last_error = f"Timeout after {self.timeout}s"
                except httpx.ConnectError as e:
                    last_error = f"Connection error: {e}"
                except httpx.TooManyRedirects:
                    last_error = "Too many redirects"
                except Exception as e:
                    last_error = str(e)[:100]

                if attempt < max_retries:
                    backoff = (2 ** attempt) * 0.5
                    await asyncio.sleep(backoff)

        response = Response(
            url=url, status=0, text="", headers={},
            elapsed=0.0, method=method.upper(), error=last_error,
        )
        self.history.append(response)
        return response

    async def get(self, url: str, **kwargs)  -> Response:
        return await self.request("GET",    url, **kwargs)

    async def post(self, url: str, **kwargs) -> Response:
        return await self.request("POST",   url, **kwargs)

    async def put(self, url: str, **kwargs)  -> Response:
        return await self.request("PUT",    url, **kwargs)

    async def patch(self, url: str, **kwargs)-> Response:
        return await self.request("PATCH",  url, **kwargs)

    async def delete(self, url: str, **kwargs)->Response:
        return await self.request("DELETE", url, **kwargs)

    async def head(self, url: str, **kwargs) -> Response:
        return await self.request("HEAD",   url, **kwargs)

    async def options(self, url: str, **kwargs)->Response:
        return await self.request("OPTIONS",url, **kwargs)

    async def bulk(
        self,
        requests: list[tuple[str, str]],
        **kwargs,
    ) -> list[Response]:

        tasks = [self.request(method, url, **kwargs) for method, url in requests]
        return await asyncio.gather(*tasks)

    def set_auth(self, token: str, scheme: str = "Bearer"):
        """Injeta Authorization header em todos os requests futuros."""
        self.extra_headers["Authorization"] = f"{scheme} {token}"
        if self._client:
            self._client.headers["Authorization"] = f"{scheme} {token}"

    def set_cookie(self, name: str, value: str):
        """Adiciona cookie à sessão."""
        self.extra_cookies[name] = value
        if self._client:
            self._client.cookies.set(name, value)

    def clear_history(self):
        self.history.clear()

    @property
    def last(self) -> Optional[Response]:
        return self.history[-1] if self.history else None

    @property
    def errors(self) -> list[Response]:
        return [r for r in self.history if r.error]

    @property
    def successful(self) -> list[Response]:
        return [r for r in self.history if r.ok]