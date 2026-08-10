<?php

function loadSession($rawCookie) {
    return unserialize($rawCookie);
}
