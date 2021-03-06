'use strict';
const dotenv = require('dotenv').config();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const pool = require('../utils/dbCon');
/* istanbul ignore next */
const accountSid = process.env.TWILIO_ACCOUNT_SID || process.env.TWILIO_ACCOUNT_SID_TEST;
/* istanbul ignore next */
const authTokenTwilio = process.env.TWILIO_AUTH_TOKEN || process.env.TWILIO_AUTH_TOKEN_TEST;
const stackingupSid = process.env.STACKINGUP_SID;
const client = require('twilio')(accountSid, authTokenTwilio);
const secret = process.env.JWT_SECRET || 'stackingupsecretlocal';

/* istanbul ignore next */
if (dotenv.error) console.warn('Warning: error reading .env file: ', dotenv.error);

module.exports.login = function login (req, res, next) {
  const { username, password } = req.credentials.value;

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

  if (authToken) {
    try {
      const decoded = jwt.verify(authToken, process.env.JWT_SECRET || 'stackingupsecretlocal');

      if (decoded.role !== 'USER') {
        res.status(403).send('User already verified.');
        return;
      }
      pool.query('SELECT "phoneNumber" FROM "User" WHERE "id" = $1', [decoded.userId]).then(result => {
        const phoneNumber = result.rows[0].phoneNumber;

        if (!phoneNumber || result.rows.length === 0) {
          res.status(400).send('Missing phone number');
          return;
        }

        const phoneNumberSTR = phoneNumber.toString().replace(/\s/g, '');
        if (!(phoneNumberSTR.substring(3).length === 9 && /^[+]{1}34[67]{1}[0-9]{8}$/.test(phoneNumberSTR))) {
          res.status(400).send('Invalid phone number');
          return;
        }

        try {
          client.verify.services(stackingupSid.toString())
            .verifications
            .create({ to: phoneNumberSTR, channel: 'sms', locale: 'es' });
          // Se queda esperando en status "pending"
          res.status(201).send('Verification code sent');
        } catch (err) {
          /* istanbul ignore next */
          console.error(err);
          /* istanbul ignore next */
          res.status(500).send('Internal server error');
        }
      });
    } catch (err) {
      if (err instanceof jwt.JsonWebTokenError) {
        res.status(401).send(`Unauthorized: ${err.message}`);
      } else {
        res.status(500).send('Internal Server Error');
      }
    }
  } else {
    res.status(401).send('Unauthorized');
  }
};

module.exports.putVerify = function putVerify (req, res, next) {
  const authToken = req.cookies?.authToken;
  const code = req.swagger.params.code?.value?.code?.toString();

  if (authToken) {
    try {
      const decoded = jwt.verify(authToken, process.env.JWT_SECRET || 'stackingupsecretlocal');

      if (decoded.role !== 'USER') {
        res.status(403).send('User already verified.');
        return;
      }

      if (!code || !(code.length === 7 && /^[0-9]{7}$/.test(code))) {
        res.status(400).send('Invalid verification code');
        return;
      }

      pool.query('SELECT "phoneNumber" FROM "User" WHERE "id" = $1', [decoded.userId]).then(result => {
        const phoneNumber = result.rows[0].phoneNumber;

        if (!phoneNumber || result.rows.length === 0) {
          res.status(400).send('Missing phone number');
          return;
        }

        const phoneNumberSTR = phoneNumber.toString().replace(/\s/g, '');
        /* istanbul ignore next */
        if (!(phoneNumberSTR.substring(3).length === 9 && /^[+]{1}34[67]{1}[0-9]{8}$/.test(phoneNumberSTR))) {
          res.status(400).send('Invalid phone number');
          return;
        }

        /* istanbul ignore next */
        try {
          client.verify.services(stackingupSid.toString())
            .verificationChecks
            .create({ to: phoneNumberSTR, code: code })
            .then(verificationCheck => {
              if (verificationCheck.status !== 'approved') {
                res.status(400).send('Error when verifying this number. Wrong code.');
                return;
              }
              pool.query('UPDATE "Auth" SET "role" = $1 WHERE "userId" = $2', ['VERIFIED', decoded.userId]).then(() => {
                pool.query('SELECT "role" FROM "Auth" WHERE "userId" = $1', [decoded.userId]).then(result => {
                  if (result.rows[0].role !== 'VERIFIED') {
                    res.status(500).send('Internal server error. User role not changed.');
                    return;
                  }
                  try {
                    const token = jwt.sign({
                      email: decoded.email,
                      role: 'VERIFIED',
                      userId: decoded.userId
                    }, secret, { expiresIn: '24h' });

                    /* istanbul ignore next */
                    const secure = process.env.COOKIE_DOMAIN ? 'Secure;' : ';';

                    res.setHeader('Set-Cookie',
                      `authToken=${token}; HttpOnly; ${secure} Max-Age=${60 * 60 * 24}; Path=/; Domain=${process.env.COOKIE_DOMAIN || 'localhost'}`
                    ).status(200).send('Phone number verified and refreshed user token');
                  } catch (err) {
                    /* istanbul ignore next */
                    res.status(500).send('Internal server error');
                  }
                });
              });
            });
        } catch (err) {
          console.error(err);
          res.status(500).send('Internal server error');
        }
      });
    } catch (err) {
      if (err instanceof jwt.JsonWebTokenError) {
        res.status(401).send(`Unauthorized: ${err.message}`);
      } else {
        res.status(500).send('Internal Server Error');
      }
    }
  } else {
    res.status(401).send('Unauthorized');
  }
};

module.exports.putSuscribed = function putSuscribed (req, res, next) {
  const authToken = req.cookies?.authToken;

  if (authToken) {
    try {
      const decoded = jwt.verify(authToken, process.env.JWT_SECRET || 'stackingupsecretlocal');

      if (decoded.role !== 'VERIFIED') {
        res.status(403).send('User must be verified to suscribe.');
        return;
      }

      pool.query('UPDATE "Auth" SET "role" = $1 WHERE "userId" = $2', ['SUBSCRIBED', decoded.userId]).then(() => {
        pool.query('SELECT "role" FROM "Auth" WHERE "userId" = $1', [decoded.userId]).then(result => {
          if (result.rows[0].role !== 'SUBSCRIBED') {
            res.status(500).send('Internal server error. User role not changed.');
            return;
          }
          try {
            const token = jwt.sign({
              email: decoded.email,
              role: 'SUBSCRIBED',
              userId: decoded.userId
            }, secret, { expiresIn: '24h' });

            /* istanbul ignore next */
            const secure = process.env.COOKIE_DOMAIN ? 'Secure;' : ';';

            res.setHeader('Set-Cookie',
              `authToken=${token}; HttpOnly; ${secure} Max-Age=${60 * 60 * 24}; Path=/; Domain=${process.env.COOKIE_DOMAIN || 'localhost'}`
            ).status(200).send('User SUBSCRIBED and refreshed user token');
          } catch (err) {
            /* istanbul ignore next */
            res.status(500).send('Internal server error');
          }
        });
      });
    } catch (err) {
      if (err instanceof jwt.JsonWebTokenError) {
        res.status(401).send(`Unauthorized: ${err.message}`);
      } else {
        res.status(500).send('Internal Server Error');
      }
    }
  } else {
    res.status(401).send('Unauthorized');
  }
};

module.exports.changePassword = function changePassword (req, res, next) {
  const authToken = req.cookies?.authToken;
  const oldPassword = req.swagger.params.passwords?.value?.oldPassword?.toString();
  const newPassword = req.swagger.params.passwords?.value?.newPassword?.toString();

  if (authToken) {
    try {
      const decoded = jwt.verify(authToken, process.env.JWT_SECRET || 'stackingupsecretlocal');

      if (!oldPassword || !newPassword) {
        res.status(400).send('Missing password');
        return;
      }

      // oldPassword must match with the one in the database
      pool.query('SELECT "password" FROM "Auth" WHERE "userId" = $1', [decoded.userId]).then(result => {
        if (!bcrypt.compareSync(oldPassword, result.rows[0].password)) {
          res.status(400).send('Wrong old password');
          return;
        }

        if (oldPassword === newPassword) {
          res.status(400).send('New password must be different from the old one');
          return;
        }

        // newPassword must be validated and then encrypted and updated in database
        if (!newPassword.toString().match(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$/)) {
          res.status(400).send('Password must contain at least one number, one lowercase and one uppercase letter, and at least 8 characters long');
          return;
        }

        pool.query('UPDATE "Auth" SET "password" = $1 WHERE "userId" = $2', [bcrypt.hashSync(newPassword, 10), decoded.userId]).then(() => {
          res.status(200).send('Password changed succesfully');
        }).catch(err => {
          console.error(err);
          res.status(500).send('Internal server error');
        });
      }).catch(err => {
        console.error(err);
        res.status(500).send('Internal server error');
      });
    } catch (err) {
      if (err instanceof jwt.JsonWebTokenError) {
        res.status(401).send(`Unauthorized: ${err.message}`);
      } else {
        res.status(500).send('Internal Server Error');
      }
    }
  } else {
    res.status(401).send('Unauthorized');
  }
};
