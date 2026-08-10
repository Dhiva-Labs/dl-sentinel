'use strict';

const fs = require('fs');
const path = require('path');

function readUpload(req) {
  return fs.readFileSync('/data/uploads/' + req.params.filename, 'utf8');
}

function readUploadJoined(req, baseDir) {
  return fs.readFileSync(path.join(baseDir, req.query.name));
}

module.exports = { readUpload, readUploadJoined };
