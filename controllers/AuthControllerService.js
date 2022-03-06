'use strict';

const { Pool } = require('pg');
const connectionString = process.env.DATABASE_URL || 'postgresql://stackingup:stackingup-local@localhost:5432/data';

const pool = new Pool({connectionString});

module.exports.login = function login (req, res, next) {
  res.send({
    message: 'This is the mockup controller for login'
  });
};