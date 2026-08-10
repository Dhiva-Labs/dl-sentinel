'use strict';

const crypto = require('crypto');

// Hash the user's password before storing it.
function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

module.exports = { hashPassword };
