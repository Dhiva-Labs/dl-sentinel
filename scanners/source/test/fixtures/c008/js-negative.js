'use strict';

const https = require('https');

function fetchSecure(url) {
  return https.get(url, { rejectUnauthorized: true }, (res) => res);
}

function fetchDefault(url) {
  return https.get(url, (res) => res);
}

module.exports = { fetchSecure, fetchDefault };
