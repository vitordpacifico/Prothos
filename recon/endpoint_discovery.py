import asyncio
from core.requester import Requester
from cfg import TARGET

async def discover(wordlist):

    requester = Requester(10)

    found = []

    for word in wordlist:

        url = f"{TARGET}/{word}"

        r = await requester.request("GET", url)

        if r.get("status") not in [404, 400]:

            print("endpoint encontrado:", url)
            found.append(url)

    return found