const express = require('express');
const { Pool } = require('pg');

const DEFAULT_ROLE = 'member';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const router = express.Router();

router.get('/', async (req, res) => {
  const result = await pool.query(`SELECT id, name, email FROM users WHERE role = '${DEFAULT_ROLE}' ORDER BY name`); // EVAL-SAFE
  res.json(result.rows);
});

module.exports = router;
