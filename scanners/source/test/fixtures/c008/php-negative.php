<?php

function fetchSecure($url) {
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    return curl_exec($ch);
}
