'use strict';

const fs = require('fs');

function makeWorldWritable(path) {
  fs.chmodSync(path, 0o777);
}

module.exports = { makeWorldWritable };
