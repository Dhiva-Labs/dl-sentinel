<?php

function fetchInsecure($url) {
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    return curl_exec($ch);
}
