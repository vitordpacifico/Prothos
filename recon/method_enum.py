methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]

async def enum_methods(url, requester):

    supported = []

    for m in methods:

        r = await requester.request(m, url)

        if r.get("status") not in [405, 404]:

            supported.append(m)

    return supported