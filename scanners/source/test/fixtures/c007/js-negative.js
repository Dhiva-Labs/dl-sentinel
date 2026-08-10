'use strict';

// Pick a random pastel color for the next chart bar.
function nextBarColor() {
  return Math.random() * 360;
}

module.exports = { nextBarColor };
