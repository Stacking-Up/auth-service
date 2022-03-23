'use-strict';

const authTest = require('./suites/auth.test');
const pool = require('../utils/dbCon');
const bcrypt = require('bcrypt');
const server = require('../server');

describe('Unit testing', () => {
    before( (done) => {
        server.deploy('test').then( () => done());
    });

    describe('Auth Tests', authTest.bind(this, pool, bcrypt));

    after( (done) => {
        server.undeploy();
        done();
    });
});