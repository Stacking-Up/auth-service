'use strict';

const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const { Pool } = require('pg');
const connectionString = process.env.DATABASE_URL || 'postgresql://stackingup:stackingup-local@localhost:5432/data';
const pool = new Pool({ connectionString });

module.exports.login = function login (req, res, next) {
  const { username, password } = req.credentials.value;
  const secret = process.env.JWT_SECRET || 'stackingupsecretlocal';

  pool.query('SELECT * FROM "Auth" WHERE "email" = $1', [username], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Error trying to connect to the database');
    }

    if (result.rows.length === 0 || !bcrypt.compareSync(password, result.rows[0].password)) {
      return res.status(400).send('Invalid username or password');
    } else {
      const token = jwt.sign({
        email: result.rows[0].email,
        role: result.rows[0].role,
        userId: result.rows[0].userId
      }, secret, { expiresIn: '1h' });
      return res.status(200).send(token);
    }
  });
};
