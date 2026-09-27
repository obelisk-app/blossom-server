/**
 * Hot-reloaded pubkey allowlist files for storage rules (`rule.pubkeysFile`).
 *
 * The file is plain text: one hex pubkey per line, `#` starts a comment,
 * blank lines are ignored. It is meant to be written by another process —
 * a web-of-trust sync, an invite bot, an operator's editor — so a large or
 * frequently-changing list doesn't live in config.yml and doesn't need a
 * restart. Writers should replace the file atomically (write + rename).
 *
 * The file is re-read when its mtime changes, checked at most once every
 * RECHECK_MS per path. A missing or unreadable file is an EMPTY list: a
 * pubkey-scoped rule then matches nobody, so the server fails closed rather
 * than open.
 */

import type { StorageRule } from "./schema.ts";

const RECHECK_MS = 2_000;
const HEX64 = /^[0-9a-f]{64}$/;

interface Entry {
  set: Set<string>;
  mtimeMs: number | null;
  checkedAt: number;
  warned: boolean;
}

const cache = new Map<string, Entry>();

export function parsePubkeysFile(text: string): Set<string> {
  const set = new Set<string>();
  for (const raw of text.split("\n")) {
    const line = raw.replace(/#.*$/, "").trim().toLowerCase();
    if (HEX64.test(line)) set.add(line);
  }
  return set;
}

/** The current contents of a pubkeys file, reloaded when it changes. */
export function loadPubkeysFile(path: string, now = Date.now()): Set<string> {
  let entry = cache.get(path);
  if (entry && now - entry.checkedAt < RECHECK_MS) return entry.set;

  if (!entry) {
    entry = { set: new Set(), mtimeMs: null, checkedAt: 0, warned: false };
    cache.set(path, entry);
  }
  entry.checkedAt = now;

  try {
    const mtimeMs = Deno.statSync(path).mtime?.getTime() ?? 0;
    if (mtimeMs !== entry.mtimeMs) {
      entry.set = parsePubkeysFile(Deno.readTextFileSync(path));
      entry.mtimeMs = mtimeMs;
      entry.warned = false;
      console.log(`[rules] Loaded ${entry.set.size} pubkeys from ${path}`);
    }
  } catch (err) {
    if (!entry.warned) {
      console.warn(`[rules] Cannot read pubkeysFile ${path}; treating it as empty:`, err);
      entry.warned = true;
    }
    entry.set = new Set();
    entry.mtimeMs = null;
  }
  return entry.set;
}

/** Test hook. */
export function clearPubkeysFileCache(): void {
  cache.clear();
}

/** Does this rule restrict uploads to a set of pubkeys (inline or from a file)? */
export function ruleIsPubkeyScoped(rule: StorageRule): boolean {
  return (rule.pubkeys?.length ?? 0) > 0 || !!rule.pubkeysFile;
}

/** Is `pubkey` in the rule's inline `pubkeys` or its `pubkeysFile`? */
export function ruleHasPubkey(rule: StorageRule, pubkey: string): boolean {
  if (rule.pubkeys?.includes(pubkey)) return true;
  if (rule.pubkeysFile) return loadPubkeysFile(rule.pubkeysFile).has(pubkey);
  return false;
}
