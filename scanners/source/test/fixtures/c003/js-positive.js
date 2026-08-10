'use strict';

function findUserByName(db, name) {
  const query = "SELECT * FROM users WHERE name = '" + name + "'";
  return db.query(query);
}

module.exports = { findUserByName };
