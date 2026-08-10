'use strict';

const https = require('https');

function fetchInsecure(url) {
  return https.get(url, { rejectUnauthorized: false }, (res) => res);
}

module.exports = { fetchInsecure };
