const fs = require('node:fs/promises');
const path = require('node:path');

const UPLOAD_DIR = path.resolve(process.cwd(), 'uploads');

async function readUpload(file) {
  const content = await fs.readFile(path.join(UPLOAD_DIR, file), 'utf8'); // EVAL-SINK
  return content;
}

module.exports = { readUpload };
