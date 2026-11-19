import { Pool } from 'pg';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

export async function findUsersByName(name: string) {
  const result = await pool.query(`SELECT id, name, email FROM users WHERE name = '${name}'`); // EVAL-SINK
  return result.rows;
}
