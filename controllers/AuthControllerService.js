'use strict';

const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const pool = require('../utils/dbCon');

module.exports.login = function login (req, res, next) {
  const { username, password } = req.credentials.value;
  const secret = process.env.JWT_SECRET || 'stackingupsecretlocal';

  if (username === undefined || password === undefined) {
    return res.status(400).send('Missing username or password');
  }

  if (!username.match(/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/)) {
    res.status(400).send('Invalid email. Please provide a valid email');
    return;
  }

  pool.query('SELECT * FROM "Auth" WHERE "email" = $1', [username]).then(result => {
    if (result.rows.length === 0 || !bcrypt.compareSync(password, result.rows[0].password)) {
      res.status(400).send('Invalid username or password');
      return;
    }

    const token = jwt.sign({
      email: result.rows[0].email,
      role: result.rows[0].role,
      userId: result.rows[0].userId
    }, secret, { expiresIn: '24h' });

    /* istanbul ignore next */
    const secure = process.env.COOKIE_DOMAIN ? 'Secure;' : ';';

    res.setHeader('Set-Cookie',
      `authToken=${token}; HttpOnly; ${secure} Max-Age=${60 * 60 * 24}; Path=/; Domain=${process.env.COOKIE_DOMAIN || 'localhost'}`
    ).status(200).send({
      email: result.rows[0].email,
      role: result.rows[0].role,
      userId: result.rows[0].userId
    });
  })
    .catch(err => {
      console.error(err);
      res.status(500).send('Internal server error');
    });
};

module.exports.logout = function logout (req, res, next) {
  try {
    res.setHeader('Set-Cookie',
    `authToken=; Max-Age=-1; Path=/; Domain=${process.env.COOKIE_DOMAIN || 'localhost'}`
    ).status(200).send('Logged out');
  } catch (err) {
    /* istanbul ignore next */
    res.status(500).send('Internal server error');
  }
};
