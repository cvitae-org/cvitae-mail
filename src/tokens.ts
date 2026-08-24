/**
 * The refresh token, on disk, readable by nobody else.
 *
 * One small file with one long-lived secret in it. The access token is not
 * stored — it lives about an hour, and writing it to disk would mean two things
 * to keep in step for no gain. It is cached in memory instead, in `oauth.ts`.
 *
 * Permissions are set explicitly rather than left to the umask: `0700` on the
 * directory and `0600` on the file. A default umask of `022` would otherwise
 * produce a world-readable mailbox credential on a shared machine, which is the
 * kind of thing that is only ever noticed afterwards.
 *
 * Writes go through a temp file and a rename so a crash mid-write leaves the
 * previous token rather than half of one. The temp name carries a UUID, not the
 * pid: two writes from the same process would otherwise collide on the same
 * path, which is a real defect the runtime's own review caught in `cvDocument`.
 */

import { randomUUID } from 'node:crypto';
import { chmod, mkdir, readFile, rename, unlink, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { config, tokenPath } from './config.js';

export type StoredTokens = {
  refresh_token: string;
  /** The address consent was granted for. Shown by `/health`. */
  email: string;
  /** Space-separated, as Google returns them. Recorded to detect a scope change. */
  scope: string;
  connected_at: string;
};

export const readTokens = async (): Promise<StoredTokens | undefined> => {
  try {
    const raw = await readFile(tokenPath(), 'utf8');
    const parsed = JSON.parse(raw) as StoredTokens;

    return parsed.refresh_token ? parsed : undefined;
  } catch {
    // Missing is the ordinary state before `/connect`, and unreadable is
    // indistinguishable from missing as far as the caller is concerned: either
    // way the remedy is to connect again.
    return undefined;
  }
};

export const writeTokens = async (tokens: StoredTokens): Promise<void> => {
  const path = tokenPath();
  const temporary = `${path}.${randomUUID()}.tmp`;

  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  // `mkdir` only applies its mode when it creates the directory, so an existing
  // one keeps whatever it had. Setting it again is what makes this idempotent.
  await chmod(dirname(path), 0o700);

  await writeFile(temporary, JSON.stringify(tokens, null, 2), { mode: 0o600 });

  try {
    await rename(temporary, path);
  } catch (error) {
    await unlink(temporary).catch(() => undefined);
    throw error;
  }
};

export const clearTokens = async (): Promise<void> => {
  await unlink(tokenPath()).catch(() => undefined);
};

export const homeDirectory = (): string => config.home;
