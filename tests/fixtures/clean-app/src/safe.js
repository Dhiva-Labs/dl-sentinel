'use strict';

// Fixture module with no known insecure patterns; a negative control for
// DL Sentinel scanner tests. Not a real application.

const { execFile } = require('child_process');
const crypto = require('crypto');
const https = require('https');

// Safe: fixed executable, arguments passed as an array — no shell, no
// string concatenation.
function runUserReport(username, callback) {
  execFile('report-tool', ['--user', username, '--format', 'json'], callback);
}

// Safe: parameterized query, no string concatenation.
function findUserByName(db, name) {
  return db.query('SELECT * FROM users WHERE name = $1', [name]);
}

// Safe: a password-hashing KDF instead of a fast general-purpose hash.
function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

// Safe: TLS certificate verification left enabled (the default).
function fetchSecure(url) {
  return https.get(url, (res) => res);
}

// Safe: configuration read from the environment, never hardcoded.
const apiKey = process.env.API_KEY;

module.exports = { runUserReport, findUserByName, hashPassword, fetchSecure, apiKey };
