import aiohttp

class Requester:

    def __init__(self, timeout):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.session = None

    async def start(self):
        self.session = aiohttp.ClientSession(timeout=self.timeout)

    async def close(self):
        await self.session.close()

    async def request(self, method, url, **kwargs):

        try:
            async with self.session.request(method, url, **kwargs) as resp:

                text = await resp.text()

                return {
                    "status": resp.status,
                    "text": text,
                    "headers": dict(resp.headers)
                }

        except Exception as e:
            return {"error": str(e)}