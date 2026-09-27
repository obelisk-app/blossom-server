import { assert, assertEquals } from "@std/assert";
import { join } from "@std/path";
import {
  clearPubkeysFileCache,
  loadPubkeysFile,
  parsePubkeysFile,
  ruleHasPubkey,
  ruleIsPubkeyScoped,
} from "../../src/config/pubkeys-file.ts";
import { getFileRule } from "../../src/prune/rules.ts";
import { StorageRuleSchema } from "../../src/config/schema.ts";

const A = "a".repeat(64);
const B = "b".repeat(64);
const C = "c".repeat(64);

Deno.test("parsePubkeysFile: one hex key per line, comments and junk ignored", () => {
  const set = parsePubkeysFile(
    `# web of trust, hop <= 1\n${A}\n  ${B.toUpperCase()}  # trailing comment\n\nnot-a-key\n${"d".repeat(63)}\n`,
  );
  assertEquals([...set].sort(), [A, B]);
});

Deno.test("StorageRuleSchema: accepts pubkeysFile", () => {
  const rule = StorageRuleSchema.parse({ type: "*", expiration: "1 year", pubkeysFile: "./wot.txt" });
  assertEquals(rule.pubkeysFile, "./wot.txt");
  assert(ruleIsPubkeyScoped(rule));
  assert(!ruleIsPubkeyScoped(StorageRuleSchema.parse({ type: "*", expiration: "1 day" })));
});

Deno.test("loadPubkeysFile: reloads when the file changes, not before", async () => {
  clearPubkeysFileCache();
  const dir = await Deno.makeTempDir();
  const path = join(dir, "wot.txt");
  try {
    await Deno.writeTextFile(path, `${A}\n`);
    assertEquals([...loadPubkeysFile(path, 1_000)], [A]);

    // Rewrite with a different mtime; within the recheck window the cached set is returned.
    await Deno.writeTextFile(path, `${B}\n`);
    await Deno.utime(path, new Date(), new Date(Date.now() + 5_000));
    assertEquals([...loadPubkeysFile(path, 1_500)], [A]);

    // After the window the change is picked up.
    assertEquals([...loadPubkeysFile(path, 5_000)], [B]);
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("loadPubkeysFile: a missing file is an empty list (fail closed)", () => {
  clearPubkeysFileCache();
  const set = loadPubkeysFile("/nonexistent/obelisk/wot.txt");
  assertEquals(set.size, 0);
});

Deno.test("getFileRule: pubkeysFile gates uploads like inline pubkeys", async () => {
  clearPubkeysFileCache();
  const dir = await Deno.makeTempDir();
  const tier1 = join(dir, "tier1.txt");
  const tier2 = join(dir, "tier2.txt");
  try {
    await Deno.writeTextFile(tier1, `${A}\n`);
    await Deno.writeTextFile(tier2, `${B}\n`);
    const rules = [
      StorageRuleSchema.parse({ type: "*", expiration: "1 year", pubkeysFile: tier1 }),
      StorageRuleSchema.parse({ type: "*", expiration: "1 month", pubkeysFile: tier2 }),
      StorageRuleSchema.parse({ type: "*", expiration: "1 week", pubkeys: [C] }),
    ];

    assertEquals(getFileRule({ mimeType: "text/javascript", pubkey: A }, rules, true)?.expiration, "1 year");
    assertEquals(getFileRule({ mimeType: "text/javascript", pubkey: B }, rules, true)?.expiration, "1 month");
    assertEquals(getFileRule({ mimeType: "text/javascript", pubkey: C }, rules, true)?.expiration, "1 week");
    assertEquals(getFileRule({ mimeType: "text/javascript", pubkey: "e".repeat(64) }, rules, true), null);
    assertEquals(getFileRule({ mimeType: "text/javascript" }, rules, true), null);
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("ruleHasPubkey: inline pubkeys and pubkeysFile combine", async () => {
  clearPubkeysFileCache();
  const dir = await Deno.makeTempDir();
  const path = join(dir, "wot.txt");
  try {
    await Deno.writeTextFile(path, `${A}\n`);
    const rule = StorageRuleSchema.parse({ type: "*", expiration: "1 year", pubkeys: [B], pubkeysFile: path });
    assert(ruleHasPubkey(rule, A));
    assert(ruleHasPubkey(rule, B));
    assert(!ruleHasPubkey(rule, C));
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});
