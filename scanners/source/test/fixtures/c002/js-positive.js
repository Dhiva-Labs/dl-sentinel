'use strict';

function runExpression(userInput) {
  return eval(userInput);
}

function buildHandler(code) {
  return new Function('data', code);
}

module.exports = { runExpression, buildHandler };
