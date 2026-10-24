import { exec } from 'node:child_process';
import { promisify } from 'node:util';

const execAsync = promisify(exec);

export async function pingHost(host: string) {
  const { stdout } = await execAsync(`ping -c 1 ${host}`); // EVAL-SINK
  return stdout;
}
