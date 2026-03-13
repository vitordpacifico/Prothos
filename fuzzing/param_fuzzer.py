async def fuzz_params(url, params, requester):

    findings = []

    for p in params:

        payload = {p: "test"}

        r = await requester.request(
            "GET",
            url,
            params=payload
        )

        if r["status"] == 500:

            findings.append({
                "param": p,
                "issue": "server_error"
            })

    return findings