'use strict';

const fs = require('fs');

function fixPermissions(path) {
  fs.chmodSync(path, 0o644);
}

module.exports = { fixPermissions };
