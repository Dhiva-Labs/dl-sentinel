'use strict';

const { exec, execFile } = require('child_process');

function runReportSafe(username) {
  execFile('report-tool', ['--user', username], (err, stdout) => {
    if (err) throw err;
    console.log(stdout);
  });
}

function runFixed() {
  exec('report-tool --user=fixed-account --format=json', (err, stdout) => {
    if (err) throw err;
  });
}

module.exports = { runReportSafe, runFixed };
