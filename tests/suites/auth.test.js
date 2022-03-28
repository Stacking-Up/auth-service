const assert = require('assert');
const axios = require('axios');
const sinon = require('sinon');

const host = 'http://localhost:4000';

module.exports = (pool, bcrypt) => {
  let compareSync;
  let mock;
  let hashSync;

  before(() => {
    sinon.stub(console, 'error'); // avoid consoling errors caused by tests
    compareSync = sinon.stub(bcrypt, 'compareSync');
    hashSync = sinon.stub(bcrypt, 'hashSync');
    mock = sinon.mock(pool);
  });

  afterEach(() => {
    mock.restore();
    mock = sinon.mock(pool);
  })

  /***************************************************************************
   * AUTH UNIT TESTS
   ***************************************************************************/
  it('should return code 200 when user credentials are valid', async () => {
    // fixture
    const query = 'SELECT * FROM "Auth" WHERE "email" = $1';
    const args = ['test@test.com'];
    const result = { rows: [{userId: 1, email: 'test@test.com', password: 'someencryptedpass'}] };

    // mock query
    compareSync.returns(true);
    mock.expects('query').withExactArgs(query, args).resolves(result);

    // REST call
    await axios.post(`${host}/api/v1/login`, { 
        username: 'test@test.com', 
        password: 'test' 
    }).then( (res) => {
      assert.equal(res.status, 200);
    }).catch( () => {
      assert.fail();
    });
  });

  it('should return code 400 when user credentials are not valid (bcrypt compare returns false)', async () => {
    // fixture
    const query = 'SELECT * FROM "Auth" WHERE "email" = $1';
    const args = ['test@test.com'];
    const result = { rows: [{userId: 1, email: 'test@test.com', password: 'someencryptedpass'}] };

    // mock query
    compareSync.returns(false);
    mock.expects('query').withExactArgs(query, args).resolves(result);

    // REST call
    await axios.post(`${host}/api/v1/login`, { 
        username: 'test@test.com', 
        password: 'test' 
    }).then( () => {
      assert.fail();
    }).catch( (err) => {
      assert.equal(err.response.status, 400);
    });
  });

  it('should return code 400 when user credentials are not valid (wrong username/password)', async () => {
    // fixture
    const query = 'SELECT * FROM "Auth" WHERE "email" = $1';
    const args = ['test@test.com']
    const result = { rows: [] };

    // mock query
    mock.expects('query').withExactArgs(query, args).resolves(result);

    // REST call
    await axios.post(`${host}/api/v1/login`, { 
        username: 'test@test.com', 
        password: 'test' 
    }).then( () => {
      assert.fail();
    }).catch( (err) => {
      assert.equal(err.response.status, 400);
    });
  });

  it('should return code 400 when user and/or password are undefined', async () => {
    // fixture
    const query = 'SELECT * FROM "Auth" WHERE "email" = $1';
    const args = []
    const result = { rows: [] };

    // mock query
    mock.expects('query').withExactArgs(query, args).resolves(result);

    // REST call
    await axios.post(`${host}/api/v1/login`, {
    }).then( () => {
      assert.fail();
    }).catch( (err) => {
      assert.equal(err.response.status, 400);
    });
  });

  it('should return code 400 when user is not a valid email', async () => {
    // fixture
    const query = 'SELECT * FROM "Auth" WHERE "email" = $1';
    const args = ['userinvalid']
    const result = { rows: [] };

    // mock query
    mock.expects('query').withExactArgs(query, args).resolves(result);

    // REST call
    await axios.post(`${host}/api/v1/login`, { 
        username: 'userinvalid', 
        password: 'test' 
    }).then( () => {
      assert.fail();
    }).catch( (err) => {
      assert.equal(err.response.status, 400);
    });
  });

  it('should return 500 when unexpected error occurs', async () => {
    // fixture
    const query = 'SELECT * FROM "Auth" WHERE "email" = $1';
    const args = ['test@test.com']
    const result = 'this result is invalid';

    // mock query
    mock.expects('query').withExactArgs(query, args).resolves(result);

    // REST call
    await axios.post(`${host}/api/v1/login`, { 
        username: 'test@test.com', 
        password: 'test' 
    }).then( () => {
      assert.fail();
    }).catch( (err) => {
      assert.equal(err.response.status, 500);
    });
  });

  it('should return code 200 when user logout', async () => {
    // REST call
    await axios.post(`${host}/api/v1/logout`)
    .then( (res) => {
      assert.equal(res.status, 200);
    }).catch( () => {
      assert.fail();
    });
  });

  it('should return code 201 when user credentials are valid', async () => {
    // fixture1
    const query = 'SELECT * FROM "Auth" WHERE "email" = $1';
    const args = ['testingtest@test.com'];
    const result = { rows: [] };

    // mock query1
    mock.expects('query').withExactArgs(query, args).resolves(result);

    // fixture2
    const query2 = 'INSERT INTO "User" ("name", "surname") VALUES ($1, $2) RETURNING *';
    const args2 = ['testname', 'testsurname'];
    const result2 = { rows: [{id: 1, name: args2[0], surname: args2[1], birthDate: null, sex: null, idCard: null, phoneNumber: null, location: null}] };

    // mock query2
    mock.expects('query').withExactArgs(query2, args2).resolves(result2);

    // fixture3
    const query3 = 'INSERT INTO "Auth" ("email", "password", "userId", "role") VALUES ($1, $2, $3, $4)';
    const args3 = ['testingtest@test.com', hashSync('Testing123', 10), 1, 'USER'];
    const result3 = { rows: [] };

    // mock query3
    mock.expects('query').withExactArgs(query3, args3).resolves(result3);

    // REST call
    await axios.post(`${host}/api/v1/register`, { 
        name: 'testname', 
        surname: 'testsurname',
        email: 'testingtest@test.com',
        password: 'Testing123'
    }).then( (res) => {
      assert.equal(res.status, 201);
      assert.equal(res.data, 'User with credentials created');
    }).catch( () => {
      assert.fail();
    });
  });

  it('should return code 400 invalid name, surname, email and/or password', async () => {
    const expected = 'Missing username, surname, email and/or password';

    // REST call
    await axios.post(`${host}/api/v1/register`, { 
        name: '', 
        surname: '',
        email: '',
        password: ''
    }).then( () => {
      assert.fail();
    }).catch( (err) => {
      assert.equal(err.response.status, 400);
      assert.equal(err.response.data, expected);
    });
  });

  it('should return code 400 invalid name and surname length', async () => {
    const expected = 'Name and surname must be at least 3 characters long';

    // REST call
    await axios.post(`${host}/api/v1/register`, { 
        name: 'aa', 
        surname: 'aa',
        email: 'testingmytests@user.com',
        password: 'Password123'
    }).then( () => {
      assert.fail();
    }).catch( (err) => {
      assert.equal(err.response.status, 400);
      assert.equal(err.response.data, expected);
    });
  });

  it('should return code 400 invalid email format', async () => {
    const expected = 'Invalid email. Please provide a valid email';

    // REST call
    await axios.post(`${host}/api/v1/register`, { 
        name: 'test', 
        surname: 'test',
        email: 'invalidEmail',
        password: 'Password123'
    }).then( () => {
      assert.fail();
    }).catch( (err) => {
      assert.equal(err.response.status, 400);
      assert.equal(err.response.data, expected);
    });
  });

  it('should return code 400 invalid password', async () => {
    const expected = 'Password must contain at least one number, one lowercase and one uppercase letter, and at least 8 characters long';

    // REST call
    await axios.post(`${host}/api/v1/register`, { 
        name: 'test', 
        surname: 'test',
        email: 'testingmytests@email.com',
        password: 'invalid'
    }).then( () => {
      assert.fail();
    }).catch( (err) => {
      assert.equal(err.response.status, 400);
      assert.equal(err.response.data, expected);
    });
  });

  it('should return code 400 when email already registered', async () => {
    const expected = 'Email already registered';

    // fixture
    const query = 'SELECT * FROM "Auth" WHERE "email" = $1';
    const args = ['testingtest@test.com'];
    const result = { rows: [{ id: 1, email: 'testingtest@test.com', password: 'Someencryptedpassword1', role: 'USER', userId: 1 }] };

    // mock query
    mock.expects('query').withExactArgs(query, args).resolves(result);

    // REST call
    await axios.post(`${host}/api/v1/register`, { 
        name: 'test', 
        surname: 'test',
        email: 'testingtest@test.com',
        password: 'Testing123'
    }).then( () => {
      assert.fail();
    }).catch( (err) => {
      assert.equal(err.response.status, 400);
      assert.equal(err.response.data, expected);
    });
  });

  it('should return code 500 when unexpected error trying to check if an email exists in DB', async () => {
    // fixture1
    const query = 'SELECT * FROM "Auth" WHERE "email" = $1';
    const args = ['testingtest@test.com'];

    // mock query1
    mock.expects('query').withExactArgs(query, args).rejects()

    // REST call
    await axios.post(`${host}/api/v1/register`, { 
        name: 'testname', 
        surname: 'testsurname',
        email: 'testingtest@test.com',
        password: 'Testing123'
    }).then( (res) => {
      assert.fail()
    }).catch( (err) => {
      assert.equal(err.response.status, 500);
      assert.equal(err.response.data, 'Internal server error');
    });
  });

  it('should return code 500 when unexpected error trying to insert the user data', async () => {
    // fixture1
    const query = 'SELECT * FROM "Auth" WHERE "email" = $1';
    const args = ['testingtest@test.com'];
    const result = { rows: [] };

    // mock query1
    mock.expects('query').withExactArgs(query, args).resolves(result);

    // fixture2
    const query2 = 'INSERT INTO "User" ("name", "surname") VALUES ($1, $2) RETURNING *';
    const args2 = ['testname', 'testsurname'];

    // mock query2
    mock.expects('query').withExactArgs(query2, args2).rejects()

    // REST call
    await axios.post(`${host}/api/v1/register`, { 
        name: 'testname', 
        surname: 'testsurname',
        email: 'testingtest@test.com',
        password: 'Testing123'
    }).then( (res) => {
      assert.fail()
    }).catch( (err) => {
      assert.equal(err.response.status, 500);
      assert.equal(err.response.data, 'Internal server error');
    });
  });

  it('should return code 500 when unexpected error trying to insert the auth data of the user', async () => {
    // fixture1
    const query = 'SELECT * FROM "Auth" WHERE "email" = $1';
    const args = ['testingtest@test.com'];
    const result = { rows: [] };

    // mock query1
    mock.expects('query').withExactArgs(query, args).resolves(result);

    // fixture2
    const query2 = 'INSERT INTO "User" ("name", "surname") VALUES ($1, $2) RETURNING *';
    const args2 = ['testname', 'testsurname'];
    const result2 = { rows: [{id: 1, name: args2[0], surname: args2[1], birthDate: null, sex: null, idCard: null, phoneNumber: null, location: null}] };

    // mock query2
    mock.expects('query').withExactArgs(query2, args2).resolves(result2)

    // fixture3
    const query3 = 'INSERT INTO "Auth" ("email", "password", "userId", "role") VALUES ($1, $2, $3, $4)';
    const args3 = ['testingtest@test.com', hashSync('Testing123', 10), 1, 'USER'];

    // mock query3
    mock.expects('query').withExactArgs(query3, args3).rejects()

    // REST call
    await axios.post(`${host}/api/v1/register`, { 
        name: 'testname', 
        surname: 'testsurname',
        email: 'testingtest@test.com',
        password: 'Testing123'
    }).then( (res) => {
      assert.fail()
    }).catch( (err) => {
      assert.equal(err.response.status, 500);
      assert.equal(err.response.data, 'Internal server error');
    });
  });

}