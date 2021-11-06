<?php

// 1) get key

$cookie_value = "ClVLIh4ASCsCBE8lAxMacFMZV2hdVVotEhhUJQNVAmhSEV4sFxFeaAw"; // from browser
$cookie_data = array("showpassword"=>"no", "bgcolor"=>"#ffffff"); // from source code

$plaintext = json_encode($cookie_data); // before xor_encrypt
$encrypted = base64_decode(urldecode($cookie_value)); // after xor_encrypt

// encrypted = plaintext ^ key => key = plaintext ^ encrypted
print($plaintext ^ $encrypted);
print("\n");

// 2) use key

function xor_encrypt($text) {
    $key = "qw8J"; // pwned
    $outText = '';

    for($i=0; $i < strlen($text); $i++) {
        $outText .= $text[$i] ^ $key[$i % strlen($key)];
    }

    return $outText;
}

$payload_data = array("showpassword"=>"yes", "bgcolor"=>"#000000");

$cookie_value = urlencode(base64_encode(xor_encrypt(json_encode($payload_data))));
print($cookie_value);

?>