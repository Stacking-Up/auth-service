'use strict';

const { Pool } = require('pg');
const connectionString = process.env.DATABASE_URL || 'postgresql://stackingup:stackingup-local@localhost:5432/data';

module.exports = new Pool({ connectionString });
