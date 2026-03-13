import re
from core.requester import Requester

script_regex = r'<script.*?src="(.*?)"'

async def find_js_files(target):

    requester = Requester(10)

    r = await requester.request("GET", target)

    if "error" in r:
        return []

    html = r["text"]

    scripts = re.findall(script_regex, html)

    return scripts