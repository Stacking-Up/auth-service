'use-strict';

require('dotenv').config();
const authTest = require('./suites/auth.test');
const pool = require('../utils/dbCon');
const bcrypt = require('bcrypt');
const server = require('../server');
const jwt = require('jsonwebtoken');
const accountSid = process.env.TWILIO_ACCOUNT_SID_TEST;
const authTokenTwilio = process.env.TWILIO_AUTH_TOKEN_TEST;
const stackingupSid = process.env.STACKINGUP_SID;
const client = require('twilio')(accountSid, authTokenTwilio).verify.services(stackingupSid.toString()).verifications;
const client2 = require('twilio')(accountSid, authTokenTwilio).verify.services(stackingupSid.toString()).verificationChecks;


describe('========== UNIT TESTING ==========', () => {
    before( (done) => {
        server.deploy('test').then( () => done());
    });

    describe('Auth Tests', authTest.bind(this, pool, bcrypt, jwt, client, client2));

    after( (done) => {
        server.undeploy();
        done();
    });
});