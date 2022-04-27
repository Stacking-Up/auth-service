const assert = require('assert');
const axios = require('axios');
const sinon = require('sinon');

const host = 'http://localhost:4000';

module.exports = (pool, bcrypt, jwt, client) => {
  let compareSync;
  let mock;
  let hashSync;
  let verify;
  let twilio;

  before(() => {
    sinon.stub(console, 'error'); // avoid consoling errors caused by tests
    compareSync = sinon.stub(bcrypt, 'compareSync');
    hashSync = sinon.stub(bcrypt, 'hashSync');
    mock = sinon.mock(pool);
    verify = sinon.stub(jwt, 'verify');
    twilio = sinon.mock(client);
  });

  afterEach(() => {
    mock.restore();
    twilio.restore();
    mock = sinon.mock(pool);
    twilio=sinon.mock(client);

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

  
  // VERIFICATION PROCESS 
        
          //(POST /api/v1/verify)

  it('should return code 201 when verification code is sent (postVerify)', async () => {
    const expected = 'Verification code sent';
    const decodedJwt = { userId: 1, role: 'USER', email: 'test@test.com' };
    const query= 'SELECT "phoneNumber" FROM "User" WHERE "id" = $1';
    const args = [decodedJwt.userId];
    const result = { rows: [{phoneNumber: '+34 777 77 77 77'}] };
    const phoneNumber = result.rows[0].phoneNumber.toString().replace(/\s/g, '')
    //mock query
    mock.expects('query').withExactArgs(query, args).resolves(result);

    // Mock Auth
    verify.withArgs('testToken', 'stackingupsecretlocal').returns(decodedJwt);

    //Mock Twilio
    twilio.expects('create').withArgs({
      to: phoneNumber,
      channel: 'sms', 
      locale: 'es' 
    }).resolves();

    // REST call
    await axios.post(`${host}/api/v1/verify`, {},{
      withCredentials: true,
      headers: { Cookie: 'authToken=testToken;' }
    }
     ).then( (res) => {
      assert.equal(res.status, 201);
      assert.equal(res.data, expected)
    }).catch( () => {
      assert.fail();
    });
  })


  it('should return code 401 when authToken is missing when verifing (postVerify)', async () => {
    const expected = 'Unauthorized';

    // REST call
    await axios.post(`${host}/api/v1/verify`, {}).then( () => {
      assert.fail();
    }).catch( (err) => {
      assert.equal(err.response.status, 401);
      assert.equal(err.response.data, expected);
    })
  })

  it('Should return 401 when JWTError is thrown on verification (postVerify)', async () => {
    // Fixture
    const expected = 'Unauthorized: Invalid token';

    // Mock Auth
    verify.withArgs('testToken', 'stackingupsecretlocal').throws(new jwt.JsonWebTokenError('Invalid token'));

    // API Call
    await axios.post(`${host}/api/v1/verify`, {}, {
      withCredentials: true,
      headers: { Cookie: 'authToken=testToken;' }
    })
      .then(() => {
        assert.fail();
      }).catch(err => {
        assert.equal(err.response.status, 401);
        assert.equal(err.response.data, expected);
      });
  });

  it('should return 403 when user is already verified (postVerify)', async () => {
    // Fixture
    const expected = 'User already verified.';
    const decodedJwt = { userId: 1, role: 'VERIFIED', email: 'test@test.com' };


    // Mock Auth
    verify.withArgs('testToken', 'stackingupsecretlocal').returns(decodedJwt);

    // REST call
    await axios.post(`${host}/api/v1/verify`, {}, {
      withCredentials: true,
      headers: { Cookie: 'authToken=testToken;' }
    }).then( () => {
      assert.fail();
    }).catch( (err) => {
      assert.equal(err.response.status, 403);
      assert.equal(err.response.data, expected);
    })
  })

  it('should return 400 when phone number is missing (postVerify)', async () => {
    // Fixture
    const expected = 'Missing phone number';
    const decodedJwt = { userId: 1, role: 'USER', email: 'test@test.com' };
    const query= 'SELECT "phoneNumber" FROM "User" WHERE "id" = $1';
    const args = [decodedJwt.userId];
    const result = { rows: [{}] };

    //mock query
    mock.expects('query').withExactArgs(query, args).resolves(result);

    // Mock Auth
    verify.withArgs('testToken', 'stackingupsecretlocal').returns(decodedJwt);

    // REST call
    await axios.post(`${host}/api/v1/verify`, {},{
      withCredentials: true,
      headers: { Cookie: 'authToken=testToken;' }
    }
     ).then( () => {
      assert.fail();
    }).catch( (err) => {
      assert.equal(err.response.status, 400);
      assert.equal(err.response.data, expected)
    });
  })

  it('should return 400 when phone number is undefined (postVerify)', async () => {
    // Fixture
    const expected = 'Missing phone number';
    const decodedJwt = { userId: 1, role: 'USER', email: 'test@test.com' };
    const query= 'SELECT "phoneNumber" FROM "User" WHERE "id" = $1';
    const args = [decodedJwt.userId];
    const result = { rows: [{phoneNumber: undefined}] };

    //mock query
    mock.expects('query').withExactArgs(query, args).resolves(result);

    // Mock Auth
    verify.withArgs('testToken', 'stackingupsecretlocal').returns(decodedJwt);

    // REST call
    await axios.post(`${host}/api/v1/verify`, {},{
      withCredentials: true,
      headers: { Cookie: 'authToken=testToken;' }
    }
     ).then( () => {
      assert.fail();
    }).catch( (err) => {
      assert.equal(err.response.status, 400);
      assert.equal(err.response.data, expected)
    });
  })

  it('should return 400 when phone number is invalid (postVerify)', async () => {
    // Fixture
    const expected = 'Invalid phone number';
    const decodedJwt = { userId: 1, role: 'USER', email: 'test@test.com' };
    const query= 'SELECT "phoneNumber" FROM "User" WHERE "id" = $1';
    const args = [decodedJwt.userId];
    const result = { rows: [{phoneNumber: '+34 678 83 83 536'}] }; //diez números en el teléfono

    //mock query
    mock.expects('query').withExactArgs(query, args).resolves(result);

    // Mock Auth
    verify.withArgs('testToken', 'stackingupsecretlocal').returns(decodedJwt);

    // REST call
    await axios.post(`${host}/api/v1/verify`, {},{
      withCredentials: true,
      headers: { Cookie: 'authToken=testToken;' }
    }
     ).then( () => {
      assert.fail();
    }).catch( (err) => {
      assert.equal(err.response.status, 400);
      assert.equal(err.response.data, expected)
    });
  })

  it('should return 400 when phone number contains letters (postVerify)', async () => {
    // Fixture
    const expected = 'Invalid phone number';
    const decodedJwt = { userId: 1, role: 'USER', email: 'test@test.com' };
    const query= 'SELECT "phoneNumber" FROM "User" WHERE "id" = $1';
    const args = [decodedJwt.userId];
    const result = { rows: [{phoneNumber: '+34 678 test 56'}] }; 

    //mock query
    mock.expects('query').withExactArgs(query, args).resolves(result);

    // Mock Auth
    verify.withArgs('testToken', 'stackingupsecretlocal').returns(decodedJwt);

    // REST call
    await axios.post(`${host}/api/v1/verify`, {},{
      withCredentials: true,
      headers: { Cookie: 'authToken=testToken;' }
    }
     ).then( () => {
      assert.fail();
    }).catch( (err) => {
      assert.equal(err.response.status, 400);
      assert.equal(err.response.data, expected)
    });
  })

  it('should return 400 when phone number without prefix (postVerify)', async () => {
    // Fixture
    const expected = 'Invalid phone number';
    const decodedJwt = { userId: 1, role: 'USER', email: 'test@test.com' };
    const query= 'SELECT "phoneNumber" FROM "User" WHERE "id" = $1';
    const args = [decodedJwt.userId];
    const result = { rows: [{phoneNumber: '678 45 72 56'}] }; 

    //mock query
    mock.expects('query').withExactArgs(query, args).resolves(result);

    // Mock Auth
    verify.withArgs('testToken', 'stackingupsecretlocal').returns(decodedJwt);

    // REST call
    await axios.post(`${host}/api/v1/verify`, {},{
      withCredentials: true,
      headers: { Cookie: 'authToken=testToken;' }
    }
     ).then( () => {
      assert.fail();
    }).catch( (err) => {
      assert.equal(err.response.status, 400);
      assert.equal(err.response.data, expected)
    });
  })

  it('Should return 500 when an unexpected error is thrown (postVerify)', async () => {
    // Fixture
    const expected = 'Internal Server Error';

    // Mock Auth 
    console.error = sinon.stub(); // Avoid logging intentionally provoked error
    verify.withArgs('testToken', 'stackingupsecretlocal').throws(new Error('Unexpected Error'));

    // API Call
    await axios.post(`${host}/api/v1/verify`, {}, {
      withCredentials: true,
      headers: { Cookie: 'authToken=testToken;' }
    })
      .then(() => {
        assert.fail();
      }).catch(err => {
        assert.equal(err.response.status, 500);
        assert.equal(err.response.data, expected);
      });
  });
  

          //(PUT /api/v1/verify)

it('should return code 401 when authToken is missing when verifing (putVerify)', async () => {
  const expected = 'Unauthorized';

  // REST call
  await axios.put(`${host}/api/v1/verify`, {
    code: '1234567'
  }).then( () => {
    assert.fail();
  }).catch( (err) => {
    assert.equal(err.response.status, 401);
    assert.equal(err.response.data, expected);
  })
})

it('Should return 401 when JWTError is thrown on verification (putVerify)', async () => {
  // Fixture
  const expected = 'Unauthorized: Invalid token';

  // Mock Auth
  verify.withArgs('testToken', 'stackingupsecretlocal').throws(new jwt.JsonWebTokenError('Invalid token'));

  // API Call
  await axios.put(`${host}/api/v1/verify`, {
    code: '1234567'
  }, {
    withCredentials: true,
    headers: { Cookie: 'authToken=testToken;' }
  })
    .then(() => {
      assert.fail();
    }).catch(err => {
      assert.equal(err.response.status, 401);
      assert.equal(err.response.data, expected);
    });
});

it('should return 403 when user is already verified (putVerify)', async () => {
  // Fixture
  const expected = 'User already verified.';
  const decodedJwt = { userId: 1, role: 'VERIFIED', email: 'test@test.com' };


  // Mock Auth
  verify.withArgs('testToken', 'stackingupsecretlocal').returns(decodedJwt);

  // REST call
  await axios.put(`${host}/api/v1/verify`, {
    code: '1234567'
  }, {
    withCredentials: true,
    headers: { Cookie: 'authToken=testToken;' }
  }).then( () => {
    assert.fail();
  }).catch( (err) => {
    assert.equal(err.response.status, 403);
    assert.equal(err.response.data, expected);
  })
})

it('should return 400 when the given code does not match the pattern (putVerify)', async () => {
    // Fixture
    const expected = 'Invalid verification code';
    const decodedJwt = { userId: 1, role: 'USER', email: 'test@test.com' };
  
    // Mock Auth
    verify.withArgs('testToken', 'stackingupsecretlocal').returns(decodedJwt);
  
    // REST call
    await axios.put(`${host}/api/v1/verify`, {
      code: '123er67'
    }, {
      withCredentials: true,
      headers: { Cookie: 'authToken=testToken;' }
    }).then( () => {
      assert.fail();
    }).catch( (err) => {
      assert.equal(err.response.status, 400);
      assert.equal(err.response.data, expected);
    })
})

it('should return 400 when the given code is not composed of 7 numbers (putVerify)', async () => {
  // Fixture
  const expected = 'Invalid verification code';
  const decodedJwt = { userId: 1, role: 'USER', email: 'test@test.com' };

  // Mock Auth
  verify.withArgs('testToken', 'stackingupsecretlocal').returns(decodedJwt);

  // REST call
  await axios.put(`${host}/api/v1/verify`, {
    code: '123456'
  }, {
    withCredentials: true,
    headers: { Cookie: 'authToken=testToken;' }
  }).then( () => {
    assert.fail();
  }).catch( (err) => {
    assert.equal(err.response.status, 400);
    assert.equal(err.response.data, expected);
  })
})

it('should return 400 when phone number is missing (putVerify)', async () => {
  // Fixture
  const expected = 'Missing phone number';
  const decodedJwt = { userId: 1, role: 'USER', email: 'test@test.com' };
  const query= 'SELECT "phoneNumber" FROM "User" WHERE "id" = $1';
  const args = [decodedJwt.userId];
  const result = { rows: [{}] };

  //mock query
  mock.expects('query').withExactArgs(query, args).resolves(result);

  // Mock Auth
  verify.withArgs('testToken', 'stackingupsecretlocal').returns(decodedJwt);

  // REST call
  await axios.put(`${host}/api/v1/verify`, {
    code: '1234567'
  },{
    withCredentials: true,
    headers: { Cookie: 'authToken=testToken;' }
  }
   ).then( () => {
    assert.fail();
  }).catch( (err) => {
    assert.equal(err.response.status, 400);
    assert.equal(err.response.data, expected)
  });
})

it('should return 400 when phone number is undefined (putVerify)', async () => {
  // Fixture
  const expected = 'Missing phone number';
  const decodedJwt = { userId: 1, role: 'USER', email: 'test@test.com' };
  const query= 'SELECT "phoneNumber" FROM "User" WHERE "id" = $1';
  const args = [decodedJwt.userId];
  const result = { rows: [{phoneNumber: undefined}] };

  //mock query
  mock.expects('query').withExactArgs(query, args).resolves(result);

  // Mock Auth
  verify.withArgs('testToken', 'stackingupsecretlocal').returns(decodedJwt);

  // REST call
  await axios.put(`${host}/api/v1/verify`, {
    code: '1234567'
  },{
    withCredentials: true,
    headers: { Cookie: 'authToken=testToken;' }
  }
   ).then( () => {
    assert.fail();
  }).catch( (err) => {
    assert.equal(err.response.status, 400);
    assert.equal(err.response.data, expected)
  });
})

it('should return 400 when phone number is invalid (putVerify)', async () => {
  // Fixture
  const expected = 'Invalid phone number';
  const decodedJwt = { userId: 1, role: 'USER', email: 'test@test.com' };
  const query= 'SELECT "phoneNumber" FROM "User" WHERE "id" = $1';
  const args = [decodedJwt.userId];
  const result = { rows: [{phoneNumber: '+34 678 83 83 536'}] };

  //mock query
  mock.expects('query').withExactArgs(query, args).resolves(result);

  // Mock Auth
  verify.withArgs('testToken', 'stackingupsecretlocal').returns(decodedJwt);

  // REST call
  await axios.put(`${host}/api/v1/verify`, {
    code: '1234567'
  },{
    withCredentials: true,
    headers: { Cookie: 'authToken=testToken;' }
  }
   ).then( () => {
    assert.fail();
  }).catch( (err) => {
    assert.equal(err.response.status, 400);
    assert.equal(err.response.data, expected)
  });
})

it('should return 400 when phone number contains letters (putVerify)', async () => {
  // Fixture
  const expected = 'Invalid phone number';
  const decodedJwt = { userId: 1, role: 'USER', email: 'test@test.com' };
  const query= 'SELECT "phoneNumber" FROM "User" WHERE "id" = $1';
  const args = [decodedJwt.userId];
  const result = { rows: [{phoneNumber: '+34 678 test 56'}] }; 

  //mock query
  mock.expects('query').withExactArgs(query, args).resolves(result);

  // Mock Auth
  verify.withArgs('testToken', 'stackingupsecretlocal').returns(decodedJwt);

  // REST call
  await axios.put(`${host}/api/v1/verify`, {
    code: '1234567'
  },{
    withCredentials: true,
    headers: { Cookie: 'authToken=testToken;' }
  }
   ).then( () => {
    assert.fail();
  }).catch( (err) => {
    assert.equal(err.response.status, 400);
    assert.equal(err.response.data, expected)
  });
})

it('should return 400 when phone number without prefix (putVerify)', async () => {
  // Fixture
  const expected = 'Invalid phone number';
  const decodedJwt = { userId: 1, role: 'USER', email: 'test@test.com' };
  const query= 'SELECT "phoneNumber" FROM "User" WHERE "id" = $1';
  const args = [decodedJwt.userId];
  const result = { rows: [{phoneNumber: '678 45 72 56'}] }; 

  //mock query
  mock.expects('query').withExactArgs(query, args).resolves(result);

  // Mock Auth
  verify.withArgs('testToken', 'stackingupsecretlocal').returns(decodedJwt);

  // REST call
  await axios.put(`${host}/api/v1/verify`, {
    code: '1234567'
  },{
    withCredentials: true,
    headers: { Cookie: 'authToken=testToken;' }
  }
   ).then( () => {
    assert.fail();
  }).catch( (err) => {
    assert.equal(err.response.status, 400);
    assert.equal(err.response.data, expected)
  });
})

it('Should return 500 when an unexpected error is thrown (putVerify)', async () => {
  // Fixture
  const expected = 'Internal Server Error';

  // Mock Auth 
  console.error = sinon.stub(); // Avoid logging intentionally provoked error
  verify.withArgs('testToken', 'stackingupsecretlocal').throws(new Error('Unexpected Error'));

  // API Call
  await axios.put(`${host}/api/v1/verify`, {
    code: '1234567'
  }, {
    withCredentials: true,
    headers: { Cookie: 'authToken=testToken;' }
  })
    .then(() => {
      assert.fail();
    }).catch(err => {
      assert.equal(err.response.status, 500);
      assert.equal(err.response.data, expected);
    });
});

// PUT /api/v1/suscribe

it('should return 200 when trying to suscribe with the verified role', async () => {
  // Fixture
  const expected = 'User SUBSCRIBED and refreshed user token';
  const decodedJwt = { userId: 1, role: 'VERIFIED', email: 'test@test.com' };
  const query = 'UPDATE "Auth" SET "role" = $1 WHERE "userId" = $2';
  const args = ['SUBSCRIBED', 1];
  const result = { rows: [{role: 'SUBSCRIBED'}] };
  const query2 = 'SELECT "role" FROM "Auth" WHERE "userId" = $1';
  const args2 = [1];

  // Mock Auth
  verify.withArgs('testToken', 'stackingupsecretlocal').returns(decodedJwt);

  // mock query
  mock.expects('query').withExactArgs(query, args).resolves();
  mock.expects('query').withExactArgs(query2, args2).resolves(result);

  // REST call
  await axios.put(`${host}/api/v1/suscribe`, {}, {
    withCredentials: true,
    headers: { Cookie: 'authToken=testToken;' }
  }).then( (res) => {
    assert.equal(res.status, 200);
    assert.equal(res.data, expected);
  });
})

it('should return code 401 when authToken is missing when trying to suscribe', async () => {
  const expected = 'Unauthorized';

  // REST call
  await axios.put(`${host}/api/v1/suscribe`, {})
  .then( () => {
    assert.fail();
  }).catch( (err) => {
    assert.equal(err.response.status, 401);
    assert.equal(err.response.data, expected);
  })
})

it('Should return 401 when JWTError is thrown while suscribing', async () => {
  // Fixture
  const expected = 'Unauthorized: Invalid token';

  // Mock Auth
  verify.withArgs('testToken', 'stackingupsecretlocal').throws(new jwt.JsonWebTokenError('Invalid token'));

  // API Call
  await axios.put(`${host}/api/v1/suscribe`, {}, {
    withCredentials: true,
    headers: { Cookie: 'authToken=testToken;' }
  })
    .then(() => {
      assert.fail();
    }).catch(err => {
      assert.equal(err.response.status, 401);
      assert.equal(err.response.data, expected);
    });
});

it('should return 403 when trying to suscribe with a different role of verified', async () => {
  // Fixture
  const expected = 'User must be verified to suscribe.';
  const decodedJwt = { userId: 1, role: 'USER', email: 'test@test.com' };

  // Mock Auth
  verify.withArgs('testToken', 'stackingupsecretlocal').returns(decodedJwt);

  // REST call
  await axios.put(`${host}/api/v1/suscribe`, {}, {
    withCredentials: true,
    headers: { Cookie: 'authToken=testToken;' }
  }).then( () => {
    assert.fail();
  }).catch( (err) => {
    assert.equal(err.response.status, 403);
    assert.equal(err.response.data, expected);
  });
})

it('should return 500 when unexpected error trying to update the role to suscribed', async () => {
  // Fixture
  const expected = 'Internal server error. User role not changed.';
  const decodedJwt = { userId: 1, role: 'VERIFIED', email: 'test@test.com' };
  const query = 'UPDATE "Auth" SET "role" = $1 WHERE "userId" = $2';
  const args = ['SUBSCRIBED', 1];
  const result = { rows: [{role: 'VERIFIED'}] };
  const query2 = 'SELECT "role" FROM "Auth" WHERE "userId" = $1';
  const args2 = [1];

  // Mock Auth
  verify.withArgs('testToken', 'stackingupsecretlocal').returns(decodedJwt);

  // mock query
  mock.expects('query').withExactArgs(query, args).resolves();
  mock.expects('query').withExactArgs(query2, args2).resolves(result);

  // REST call
  await axios.put(`${host}/api/v1/suscribe`, {}, {
    withCredentials: true,
    headers: { Cookie: 'authToken=testToken;' }
  }).then( (res) => {
    assert.fail();
  }).catch((err) => {
    assert.equal(err.response.status, 500);
    assert.equal(err.response.data, expected);
  });
})

it('Should return 500 when an unexpected error is thrown when trying to suscribe', async () => {
  // Fixture
  const expected = 'Internal Server Error';

  // Mock Auth 
  verify.withArgs('testToken', 'stackingupsecretlocal').throws(new Error('Unexpected Error'));

  // API Call
  await axios.put(`${host}/api/v1/suscribe`, {}, {
    withCredentials: true,
    headers: { Cookie: 'authToken=testToken;' }
  })
    .then(() => {
      assert.fail();
    }).catch(err => {
      assert.equal(err.response.status, 500);
      assert.equal(err.response.data, expected);
    });
});

}