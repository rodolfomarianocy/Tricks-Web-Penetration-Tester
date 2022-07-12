<?php
$object = "OBJECT-PHPGGC";
$secretKey = "SECRET-KEY";
$cookie = urlencode('{"token":"' . $object . '","sig_hmac_sha1":"' . hash_hmac('sha1', $object, $secretKey) . '"}');
echo $cookie;