import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { TARGET } from "@red-cup-engineering/koios-news-cloudflare-release-engine/carrier";
import {
  attachExternalSignature,
  formCloudflareGrant,
  formCloudflareRollbackBinding,
  formEditorialGrant,
  formFirstPostHandoff,
  formRoutineEnvironment,
  readTrustedKeyMap,
  verifyCloudflareArtifact,
  verifyEditorialArtifact,
  writeCreateOnly,
} from "../src/authority-ceremony.mjs";
import {
  verifyBinding,
  verifyRollback,
} from "@red-cup-engineering/koios-news-cloudflare-release-engine/carrier";

const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const canonical = (value) => {
  if (
    value === null || typeof value === "boolean" || typeof value === "number" ||
    typeof value === "string"
  ) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${
    Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${canonical(value[key])}`
    ).join(",")
  }}`;
};
function fixture() {
  const root = mkdtempSync("/var/tmp/koios-authority-ceremony-");
  const draft = join(root, "story.md");
  writeFileSync(
    draft,
    "---\ntitle: Story\nslug: story\ndraft: true\n---\nBody\n",
  );
  const keyId = "editorial_primary_20260829",
    pair = generateKeyPairSync("ed25519"),
    keys = join(root, "keys.json");
  writeFileSync(
    keys,
    `${canonical({ [keyId]: pair.publicKey.export({ format: "jwk" }).x })}\n`,
  );
  const candidate = join(root, "candidate");
  mkdirSync(candidate);
  const index = Buffer.from("<h1>Koios</h1>\n");
  writeFileSync(join(candidate, "index.html"), index);
  writeFileSync(
    join(candidate, "manifest.json"),
    `${
      JSON.stringify({
        kind: "news-property.build-manifest/v1",
        provenance: { origin: "https://koios.news" },
        artifacts: [{
          file: "index.html",
          sha256: sha(index),
          bytes: index.length,
        }],
      })
    }\n`,
  );
  const binding = join(root, "binding.json");
  writeFileSync(
    binding,
    `${
      JSON.stringify({
        kind: "koios.news.cloudflare-release-binding/v1",
        ...TARGET,
      })
    }\n`,
  );
  return { root, draft, keyId, pair, keys, candidate, binding };
}
test("forms an exact editorial grant, attaches an external signature, and verifies against exact manuscript bytes", () => {
  const x = fixture();
  try {
    const unsigned = formEditorialGrant({
      draftPath: x.draft,
      manuscriptSlug: "story",
      grantId: "editorial_grant_20260829",
      issuerKeyId: x.keyId,
      issuedAt: "2026-08-29T12:00:00.000Z",
      expiresAt: "2026-08-29T13:00:00.000Z",
    });
    const unsignedPath = writeCreateOnly(
      join(x.root, "unsigned.json"),
      unsigned,
    );
    const signature = sign(
      null,
      Buffer.from(canonical(unsigned)),
      x.pair.privateKey,
    ).toString("base64url");
    const signed = attachExternalSignature({
      kind: "editorial",
      unsignedPath,
      signature,
      authorityKeysPath: x.keys,
    });
    const grantPath = writeCreateOnly(join(x.root, "grant.json"), signed);
    const verified = verifyEditorialArtifact({
      grantPath,
      authorityKeysPath: x.keys,
      draftPath: x.draft,
      manuscriptSlug: "story",
      now: "2026-08-29T12:30:00.000Z",
    });
    assert.equal(verified.scope, "exact-manuscript");
    assert.equal(readFileSync(grantPath, "utf8"), `${canonical(signed)}\n`);
    assert.throws(() => writeCreateOnly(grantPath, signed), /overwrite/);
  } finally {
    rmSync(x.root, { recursive: true, force: true });
  }
});
test("refuses a signature not produced over the exact canonical unsigned bytes and weak public keys", () => {
  const x = fixture();
  try {
    const unsigned = formEditorialGrant({
      draftPath: x.draft,
      manuscriptSlug: "story",
      grantId: "editorial_grant_20260829",
      issuerKeyId: x.keyId,
      issuedAt: "2026-08-29T12:00:00.000Z",
      expiresAt: "2026-08-29T13:00:00.000Z",
    });
    const unsignedPath = writeCreateOnly(
      join(x.root, "unsigned.json"),
      unsigned,
    );
    assert.throws(
      () =>
        attachExternalSignature({
          kind: "editorial",
          unsignedPath,
          signature: sign(null, Buffer.from("other"), x.pair.privateKey)
            .toString("base64url"),
          authorityKeysPath: x.keys,
        }),
      /does not verify/,
    );
    writeFileSync(
      x.keys,
      `${canonical({ [x.keyId]: Buffer.alloc(32).toString("base64url") })}\n`,
    );
    assert.throws(() => readTrustedKeyMap(x.keys), /non-small-order/);
  } finally {
    rmSync(x.root, { recursive: true, force: true });
  }
});
test("forms an inert first-post handoff that binds only current draft bytes", () => {
  const x = fixture();
  try {
    const handoff = formFirstPostHandoff({
      draftPath: x.draft,
      manuscriptSlug: "story",
    });
    assert.deepEqual(handoff.manuscript, {
      bytes: readFileSync(x.draft).length,
      digest: `sha256:${sha(readFileSync(x.draft))}`,
      requiredSourceState: "draft: true",
      slug: "story",
    });
    assert.equal(handoff.status, "inert-preparation-only");
    assert.equal(handoff.boundaries.delivery, "not-prepared");
    assert.equal(JSON.stringify(handoff).includes("signature"), false);
    assert.equal(JSON.stringify(handoff).includes("credential"), false);
    writeFileSync(x.draft, "---\ndraft: false\n---\nBody\n");
    assert.throws(
      () => formFirstPostHandoff({ draftPath: x.draft, manuscriptSlug: "story" }),
      /draft: true/,
    );
    writeFileSync(x.draft, "---\nslug: other\ndraft: true\n---\nBody\n");
    assert.throws(
      () => formFirstPostHandoff({ draftPath: x.draft, manuscriptSlug: "story" }),
      /slug/,
    );
  } finally {
    rmSync(x.root, { recursive: true, force: true });
  }
});
test("forms action-specific Cloudflare grants and exact routine job/environment artifacts without credentials", () => {
  const x = fixture();
  try {
    const grant = formCloudflareGrant({
      candidateDir: x.candidate,
      bindingPath: x.binding,
      action: "preview",
      grantId: "preview_grant_20260829",
      issuerKeyId: x.keyId,
      issuedAt: "2026-08-29T12:00:00.000Z",
      expiresAt: "2026-08-29T13:00:00.000Z",
    });
    assert.equal(grant.scope.action, "preview");
    assert.equal(grant.scope.target.hostname, "koios.news");
    const unsignedPath = writeCreateOnly(join(x.root, "preview.unsigned.json"), grant);
    const signature = sign(
      null,
      Buffer.from(canonical(grant)),
      x.pair.privateKey,
    ).toString("base64url");
    const grantPath = writeCreateOnly(
      join(x.root, "preview.grant.json"),
      attachExternalSignature({
        kind: "cloudflare",
        unsignedPath,
        signature,
        authorityKeysPath: x.keys,
      }),
    );
    const verified = verifyCloudflareArtifact({
      grantPath,
      authorityKeysPath: x.keys,
      candidateDir: x.candidate,
      bindingPath: x.binding,
      action: "preview",
      now: "2026-08-29T12:30:00.000Z",
    });
    assert.equal(verified.grant.grantId, "preview_grant_20260829");
    assert.throws(
      () => verifyCloudflareArtifact({
        grantPath,
        authorityKeysPath: x.keys,
        candidateDir: x.candidate,
        bindingPath: x.binding,
        action: "release",
        now: "2026-08-29T12:30:00.000Z",
        productionBaselinePath: join(x.root, "missing-baseline.json"),
      }),
      /production baseline/,
    );
    const environment = formRoutineEnvironment({
      KOIOS_NEWS_ROUTINE_PUBLICATION_JOB: "/secure/job.json",
      KOIOS_NEWS_ROUTINE_PUBLICATION_AUTHORITY_KEYS: "/secure/keys.json",
      KOIOS_NEWS_ROUTINE_PUBLICATION_ASSESSMENT_KEYS:
        "/secure/assessment-keys.json",
      KOIOS_NEWS_ROUTINE_PUBLICATION_OUTPUT_ROOT: "/secure/output",
      KOIOS_NEWS_ROUTINE_PUBLICATION_REPLAY_ROOT: "/secure/replay",
      KOIOS_NEWS_PROPERTY: "/secure/property.json",
    });
    assert.match(
      environment,
      /^KOIOS_NEWS_ROUTINE_PUBLICATION_JOB=\/secure\/job\.json/m,
    );
    assert.equal(environment.includes("PRIVATE"), false);
    const queueEnvironment = formRoutineEnvironment({
      KOIOS_NEWS_ROUTINE_PUBLICATION_QUEUE: "/secure/routine-jobs",
      KOIOS_NEWS_ROUTINE_PUBLICATION_AUTHORITY_KEYS: "/secure/keys.json",
      KOIOS_NEWS_ROUTINE_PUBLICATION_ASSESSMENT_KEYS:
        "/secure/assessment-keys.json",
      KOIOS_NEWS_ROUTINE_PUBLICATION_OUTPUT_ROOT: "/secure/output",
      KOIOS_NEWS_ROUTINE_PUBLICATION_REPLAY_ROOT: "/secure/replay",
      KOIOS_NEWS_PROPERTY: "/secure/property.json",
    });
    assert.match(
      queueEnvironment,
      /^KOIOS_NEWS_ROUTINE_PUBLICATION_QUEUE=\/secure\/routine-jobs/m,
    );
    assert.equal(queueEnvironment.includes("KOIOS_NEWS_ROUTINE_PUBLICATION_JOB="), false);
  } finally {
    rmSync(x.root, { recursive: true, force: true });
  }
});
test("forms a create-only rollback binding for an observed version and exact binding bytes", () => {
  const x = fixture();
  try {
    const rollback = formCloudflareRollbackBinding({
      bindingPath: x.binding,
      priorVersionId: "observed-production-version-20260829",
    });
    const output = writeCreateOnly(join(x.root, "rollback.json"), rollback);
    assert.equal(statSync(output).mode & 0o777, 0o600);
    assert.equal(readFileSync(output, "utf8"), `${canonical(rollback)}\n`);
    assert.deepEqual(verifyRollback(output, verifyBinding(x.binding)), rollback);
    assert.equal(rollback.bindingSha256, sha(readFileSync(x.binding)));
    assert.throws(
      () =>
        formCloudflareRollbackBinding({
          bindingPath: x.binding,
          priorVersionId: "",
        }),
      /priorVersionId/,
    );
    assert.throws(() => writeCreateOnly(output, rollback), /overwrite/);
  } finally {
    rmSync(x.root, { recursive: true, force: true });
  }
});
