'use strict';

const fs = require('fs');
const path = require('path');

const SAFE_DIR = '/data/uploads';

function readUpload(filename) {
  return fs.readFileSync(path.join(SAFE_DIR, path.basename(filename)));
}

function readFixed() {
  return fs.readFileSync(path.join(SAFE_DIR, 'manifest.json'));
}

module.exports = { readUpload, readFixed };
