'use strict';

// Generate a session token for the new login.
function generateSessionToken() {
  return Math.random().toString(36).slice(2);
}

module.exports = { generateSessionToken };
