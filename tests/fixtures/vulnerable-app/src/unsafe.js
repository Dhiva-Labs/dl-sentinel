'use strict';

// Deliberately insecure fixture module for DL Sentinel scanner tests.
// Not a real application; never imported or executed by anything.

const { exec } = require('child_process');
const crypto = require('crypto');
const https = require('https');
const fs = require('fs');

// Insecure: shell command built via string concatenation from user input.
function runUserReport(username) {
  const cmd = 'report-tool --user=' + username + ' --format=json';
  exec(cmd, (err, stdout) => {
    if (err) throw err;
    console.log(stdout);
  });
}

// Insecure: SQL built via string concatenation (SQL injection pattern).
function findUserByName(db, name) {
  const query = "SELECT * FROM users WHERE name = '" + name + "'";
  return db.query(query);
}

// Insecure: MD5 used to hash a password.
function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

// Insecure: TLS certificate verification disabled.
function fetchInsecure(url) {
  return https.get(url, { rejectUnauthorized: false }, (res) => res);
}

// Insecure: eval of externally-supplied input.
function runExpression(userInput) {
  return eval(userInput);
}

// Insecure: hardcoded path traversal pattern into a temp directory.
function readUserTemp(filename) {
  return fs.readFileSync('/tmp/app-cache/../../etc/' + filename, 'utf8');
}

module.exports = {
  runUserReport,
  findUserByName,
  hashPassword,
  fetchInsecure,
  runExpression,
  readUserTemp,
};
