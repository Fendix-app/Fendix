const express = require('express');
const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const router = express.Router();

async function findUsersByName(name) {
  const result = await pool.query(`SELECT id, name, email FROM users WHERE name = '${name}'`); // EVAL-SINK
  return result.rows;
}

router.get('/', async (req, res) => {
  const name = req.query.name;
  const users = await findUsersByName(name);
  res.json(users);
});

module.exports = router;
