from core.requester import Requester
from cfg import TARGET

async def map_services(wordlist):

    requester = Requester(10)

    services = []

    for service in wordlist:

        url = f"{TARGET}/{service}"

        r = await requester.request("GET", url)

        if r.get("status") not in [404]:

            print("microserviço detectado:", url)
            services.append(url)

    return services