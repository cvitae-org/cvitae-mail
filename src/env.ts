/**
 * Loads `.env` into the process, if there is one.
 *
 * Imported by the entry point and by nothing else, for the same reason the
 * runtime keeps this at its edges: a module that reads `.env` on import changes
 * its host's configuration as a side effect of being required. Whoever owns the
 * process owns the environment.
 *
 * A missing file is the normal case. Without credentials the service still
 * starts and answers `/health` with `not_configured`, which is the state the
 * runtime is written to expect.
 */

import { existsSync } from 'node:fs';

const path = process.env.ENV_FILE ?? '.env';

if (existsSync(path)) {
  // Node's own loader, so there is no dependency for this. It does not
  // overwrite variables that are already set.
  process.loadEnvFile(path);
}
