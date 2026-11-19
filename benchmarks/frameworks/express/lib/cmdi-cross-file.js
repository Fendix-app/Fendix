const { exec } = require('node:child_process');
const { promisify } = require('node:util');

const execAsync = promisify(exec);

async function pingHost(host) {
  const { stdout } = await execAsync(`ping -c 1 ${host}`); // EVAL-SINK
  return stdout;
}

module.exports = { pingHost };
