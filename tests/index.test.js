'use-strict';

const authTest = require('./suites/auth.test');

describe('Unit testing', () => {
    before(function() {
        //Before all tests
        return;
    });

    describe('Auth Tests', authTest.bind(this));
});