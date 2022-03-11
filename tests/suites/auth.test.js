const assert = require('assert');
const axios = require('axios');
const sinon = require('sinon');

const host = 'http://localhost:4000';

module.exports = (pool, bcrypt) => {
  let compareSync;
  let mock;

  before(() => {
    sinon.stub(console, 'error'); // avoid consoling errors caused by tests
    compareSync = sinon.stub(bcrypt, 'compareSync');
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
}