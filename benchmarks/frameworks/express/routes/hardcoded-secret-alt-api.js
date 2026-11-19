const express = require('express');
const { Pool } = require('pg');

const DATABASE_URL = 'postgres://app:__EVAL_DB_PASSWORD__@db.internal:5432/app'; // EVAL-SINK

const pool = new Pool({ connectionString: DATABASE_URL });
const router = express.Router();

router.get('/', async (req, res) => {
  const result = await pool.query('SELECT count(*)::int AS total FROM users');
  res.json({ users: result.rows[0].total });
});

module.exports = router;
