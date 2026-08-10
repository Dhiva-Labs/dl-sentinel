'use strict';

function parseData(input) {
  return JSON.parse(input);
}

function evaluate(expression) {
  return expression.value;
}

const Function = { create: () => {} };

module.exports = { parseData, evaluate, Function };
