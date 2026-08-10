'use strict';

function findUserByName(db, name) {
  return db.query('SELECT * FROM users WHERE name = $1', [name]);
}

function search(client, term) {
  const filter = 'status:active AND tag:' + term;
  return client.query(filter);
}

module.exports = { findUserByName, search };
