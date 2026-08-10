'use strict';

const { exec } = require('child_process');

function runReport(username) {
  const cmd = 'report-tool --user=' + username;
  exec(cmd, (err, stdout) => {
    if (err) throw err;
    console.log(stdout);
  });
}

module.exports = { runReport };
