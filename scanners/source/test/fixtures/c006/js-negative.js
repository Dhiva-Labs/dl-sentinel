'use strict';

const crypto = require('crypto');

// Compute a checksum of the uploaded file for de-duplication.
function fileChecksum(buffer) {
  return crypto.createHash('md5').update(buffer).digest('hex');
}

module.exports = { fileChecksum };
