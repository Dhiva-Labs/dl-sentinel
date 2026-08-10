import { run } from '../src/run.js';
import type { CliIO } from '../src/io.js';

export interface CaptureResult {
  code: number;
  stdout: string;
  stderr: string;
}

export interface RunOptions {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  stdoutIsTTY?: boolean;
  stderrIsTTY?: boolean;
}

/**
 * Drive the CLI in-process, capturing stdout/stderr into strings and returning
 * the exit code. Defaults to a non-TTY, empty-env host so output is plain and
 * deterministic (no color, no progress) unless a test opts in.
 */
export async function runCli(argv: string[], options: RunOptions = {}): Promise<CaptureResult> {
  let stdout = '';
  let stderr = '';
  const io: CliIO = {
    cwd: options.cwd ?? process.cwd(),
    env: options.env ?? {},
    stdout: (text) => {
      stdout += text;
    },
    stderr: (text) => {
      stderr += text;
    },
    stdoutIsTTY: options.stdoutIsTTY ?? false,
    stderrIsTTY: options.stderrIsTTY ?? false,
  };
  const code = await run(argv, io);
  return { code, stdout, stderr };
}
