'use strict';

/**
 * Example dangerous call, commented out:
 * eval(userInput);
 * exec('rm -rf ' + target);
 */

function safe() {
  return 'no-op';
}

module.exports = { safe };
