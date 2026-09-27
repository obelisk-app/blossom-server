/**
 * E2E tests for the obelisk-app additions:
 *   - storage rules with `pubkeysFile` gate PUT /upload, and pick up edits
 *     to the file without a restart;
 *   - `storage.sandboxBlobs` adds CSP sandbox + nosniff to blob responses.
 *
 * sanitizeOps/sanitizeResources are disabled for the same reason as the
 * other e2e suites: the upload worker pool's MessagePorts outlive a test.
 */

import { assertEquals } from "@std/assert";
import { encodeBase64Url } from "@std/encoding/base64url";
import { encodeHex } from "@std/encoding/hex";
import { crypto as stdCrypto } from "@std/crypto";
import { join } from "@std/path";
import { finalizeEvent, generateSecretKey, getPublicKey } from "nostr-tools/pure";
import type { Hono } from "@hono/hono";
import { initDb } from "../../src/db/client.ts";
import { LocalStorage } from "../../src/storage/local.ts";
import { initPool } from "../../src/workers/pool.ts";
import { buildApp } from "../../src/server.ts";
import { ConfigSchema } from "../../src/config/schema.ts";
import { clearPubkeysFileCache } from "../../src/config/pubkeys-file.ts";
import type { BlossomVariables } from "../../src/middleware/auth.ts";

const insider = generateSecretKey();
const outsider = generateSecretKey();
const testOpts = { sanitizeOps: false, sanitizeResources: false } as const;

async function sha256Hex(data: Uint8Array): Promise<string> {
  const buf = await stdCrypto.subtle.digest("SHA-256", data.buffer as ArrayBuffer);
  return encodeHex(new Uint8Array(buf));
}

function auth(sk: Uint8Array, hash: string): string {
  const now = Math.floor(Date.now() / 1000);
  const ev = finalizeEvent({
    kind: 24242,
    created_at: now,
    tags: [["t", "upload"], ["x", hash], ["expiration", String(now + 600)]],
    content: "Upload blob",
  }, sk);
  return `Nostr ${encodeBase64Url(new TextEncoder().encode(JSON.stringify(ev)))}`;
}

async function upload(app: Hono<{ Variables: BlossomVariables }>, sk: Uint8Array, text: string, type = "text/html") {
  const data = new TextEncoder().encode(text);
  const hash = await sha256Hex(data);
  const res = await app.fetch(new Request("http://localhost/upload", {
    method: "PUT",
    headers: {
      "Content-Length": String(data.byteLength),
      "Content-Type": type,
      "X-SHA-256": hash,
      Authorization: auth(sk, hash),
    },
    body: data,
  }));
  await res.body?.cancel();
  return { status: res.status, hash };
}

let gated: Hono<{ Variables: BlossomVariables }>;
let plain: Hono<{ Variables: BlossomVariables }>;
let listPath: string;
let cleanup: () => Promise<void>;

Deno.test({
  name: "wot-rules e2e setup",
  async fn() {
    clearPubkeysFileCache();
    const tmpDir = await Deno.makeTempDir({ prefix: "blossom_e2e_wot_" });
    const dbPath = join(tmpDir, "test.db");
    listPath = join(tmpDir, "tier1.txt");
    await Deno.writeTextFile(listPath, `# tier 1\n${getPublicKey(insider)}\n`);

    const db = await initDb({ path: dbPath });
    const storage = new LocalStorage(join(tmpDir, "blobs"));
    await storage.setup();
    const pool = initPool(1, 4, 500, db, { path: dbPath });

    gated = await buildApp(db, storage, ConfigSchema.parse({
      publicDomain: "localhost",
      upload: { enabled: true, requireAuth: true, requirePubkeyInRule: true },
      storage: {
        sandboxBlobs: true,
        rules: [{ type: "*", expiration: "1 year", pubkeysFile: listPath }],
      },
    }));
    plain = await buildApp(db, storage, ConfigSchema.parse({
      publicDomain: "localhost",
      upload: { enabled: true, requireAuth: true },
      storage: { rules: [{ type: "*", expiration: "1 year" }] },
    }));

    cleanup = async () => {
      pool.shutdown();
      db.close();
      await Deno.remove(tmpDir, { recursive: true });
    };
  },
  ...testOpts,
});

Deno.test({
  name: "pubkeysFile: a listed key uploads, an unlisted one is refused",
  async fn() {
    assertEquals((await upload(gated, insider, "<p>in</p>")).status, 201);
    assertEquals((await upload(gated, outsider, "<p>out</p>")).status, 401);
  },
  ...testOpts,
});

Deno.test({
  name: "pubkeysFile: editing the file takes effect without a restart",
  async fn() {
    await Deno.writeTextFile(listPath, `${getPublicKey(outsider)}\n`);
    // Force a distinct mtime and let the 2 s recheck window lapse.
    await Deno.utime(listPath, new Date(), new Date(Date.now() + 10_000));
    await new Promise((r) => setTimeout(r, 2_100));
    assertEquals((await upload(gated, outsider, "<p>now in</p>")).status, 201);
    assertEquals((await upload(gated, insider, "<p>now out</p>")).status, 401);
  },
  ...testOpts,
});

Deno.test({
  name: "sandboxBlobs: blobs carry CSP sandbox and nosniff; off by default",
  async fn() {
    const { hash } = await upload(plain, insider, "<script>alert(1)</script>");
    const sandboxed = await gated.fetch(new Request(`http://localhost/${hash}`));
    await sandboxed.body?.cancel();
    assertEquals(sandboxed.status, 200);
    assertEquals(sandboxed.headers.get("content-security-policy"), "default-src 'none'; sandbox");
    assertEquals(sandboxed.headers.get("x-content-type-options"), "nosniff");

    const open = await plain.fetch(new Request(`http://localhost/${hash}`));
    await open.body?.cancel();
    assertEquals(open.headers.get("content-security-policy"), null);
  },
  ...testOpts,
});

Deno.test({
  name: "wot-rules e2e teardown",
  async fn() {
    await cleanup();
  },
  ...testOpts,
});
