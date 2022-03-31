'use strict';
require('dotenv').config()
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const pool = require('../utils/dbCon');
const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const stackingupSid = process.env.STACKINGUP_SID;
const client = require('twilio')(accountSid, authToken);


module.exports.login = function login (req, res, next) {
  const { username, password } = req.credentials.value;
  const secret = process.env.JWT_SECRET || 'stackingupsecretlocal';

  if (!username || !password) {
    return res.status(400).send('Missing username or password');
  }

  if (!username.toString().match(/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/)) {
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

module.exports.register = function register (req, res, next) {
  const { name, surname, email, password } = req.user.value;

  if (!name || !surname || !email || !password) {
    res.status(400).send('Missing username, surname, email and/or password');
    return;
  }

  if (name.toString().length < 3 || surname.toString().length < 3) {
    res.status(400).send('Name and surname must be at least 3 characters long');
    return;
  }

  if (!email.toString().match(/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/)) {
    res.status(400).send('Invalid email. Please provide a valid email');
    return;
  }

  if (!password.toString().match(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$/)) {
    res.status(400).send('Password must contain at least one number, one lowercase and one uppercase letter, and at least 8 characters long');
    return;
  }

  pool.query('SELECT * FROM "Auth" WHERE "email" = $1', [email.toString().toLowerCase()])
    .then(result => {
      if (result.rows.length > 0) {
        res.status(400).send('Email already registered');
        return;
      }

      pool.query('INSERT INTO "User" ("name", "surname") VALUES ($1, $2) RETURNING *', [name.toString(), surname.toString()])
        .then(result => {
          pool.query('INSERT INTO "Auth" ("email", "password", "userId", "role") VALUES ($1, $2, $3, $4)', [email, bcrypt.hashSync(password, 10), result.rows[0].id, 'USER'])
            .then(() => {
              res.status(201).send('User with credentials created');
            })
            .catch(err => {
              console.error(err);
              res.status(500).send('Internal server error');
            });
        }).catch(err => {
          console.error(err);
          res.status(500).send('Internal server error');
        });
    }).catch(err => {
      console.error(err);
      res.status(500).send('Internal server error');
    });
};

module.exports.postVerify = function postVerify (req, res, next) {
  const authToken = req.cookies?.authToken;
  const phoneNumber = req.swagger.params.phoneNumber?.value.phoneNumber;

  if (authToken) {
    //SACAR ROL DE authToken y añadir if() para comprobar que el rol no es VERIFY
    let phoneNumberSTR = phoneNumber.toString().replace(/\s/g, '');
    if (phoneNumberSTR.substring(3).length === 9 && /^[+]{1}34[67]{1}[0-9]{8}$/.test(phoneNumberSTR)) {
      try {
        client.verify.services(stackingupSid.toString())
          .verifications
          .create({ to: phoneNumberSTR, channel: 'sms', locale: 'es' })
          .then(verification => console.log(verification.status));
        // Se queda esperando en status "pending"
        res.status(201).send('Verification code sent');
      } catch (err) {
        console.error(err);
        res.status(500).send('Internal server error');
      }
    } else {
      res.status(400).send('Invalid phone number');
      return;
    }
  } else {
    res.status(401).send('Unauthorized');
    return;
  }
};
