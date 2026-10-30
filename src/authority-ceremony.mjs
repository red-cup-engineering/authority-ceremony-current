import { createPublicKey, verify } from "node:crypto";
import {
  closeSync,
  existsSync,
  lstatSync,
  openSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { verifyPublicationAuthority } from "@red-cup-engineering/koios-news-editorial-publication-authority-engine";
import { canonicalJson } from "@red-cup-engineering/json-services-section/canonical-json";
import {
  TARGET,
  verifyBinding,
  verifyCandidate,
  verifyGrant,
  verifyProductionBaseline,
} from "@red-cup-engineering/koios-news-cloudflare-release-engine/carrier";
import { sha256Digest, sha256Hex } from "@red-cup-engineering/cryptographic-computer-data-engineering-services-section/integrity";

const EDITORIAL_KIND = "koios.news.editorial-publication-grant/v1";
const RELEASE_KIND = "koios.news.cloudflare-release-grant/v2";
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const ED25519_FIELD = (1n << 255n) - 19n;
const ED25519_ORDER = (1n << 252n) + 27742317777372353535851937790883648493n;
const ED25519_SMALL_ORDER = new Set([
  "0100000000000000000000000000000000000000000000000000000000000000",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "0000000000000000000000000000000000000000000000000000000000000080",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
]);
const object = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype;
const fail = (message) => {
  throw new TypeError(`koios authority ceremony: ${message}`);
};
const identifier = (value) =>
  typeof value === "string" && /^[A-Za-z0-9_-]{16,128}$/u.test(value);
const slug = (value) =>
  typeof value === "string" && /^[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(value);
const sha256 = (value) =>
  typeof value === "string" && /^sha256:[a-f0-9]{64}$/u.test(value);
const rawSha256 = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
const timestamp = (value) =>
  typeof value === "string" &&
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) &&
  Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
const exact = (value, keys, label) => {
  if (
    !object(value) || Object.keys(value).length !== keys.length ||
    keys.some((key) => !Object.hasOwn(value, key))
  ) fail(`${label} has an invalid shape`);
};
function b64(value, length, label) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/u.test(value)) {
    fail(`${label} must be unpadded base64url`);
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== length || bytes.toString("base64url") !== value) {
    fail(`${label} must encode exactly ${length} bytes`);
  }
  return bytes;
}
function littleEndian(bytes) {
  let number = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    number = number << 8n | BigInt(bytes[index]);
  }
  return number;
}
function strictPoint(bytes, label) {
  const y = Buffer.from(bytes);
  y[31] &= 0x7f;
  if (
    littleEndian(y) >= ED25519_FIELD ||
    ED25519_SMALL_ORDER.has(bytes.toString("hex"))
  ) fail(`${label} is not a canonical non-small-order Ed25519 point`);
}
function pathValue(value, label) {
  if (
    typeof value !== "string" || !value.startsWith("/") || /[\r\n]/u.test(value)
  ) fail(`${label} must be an absolute path without line breaks`);
  return resolve(value);
}
function environmentPath(value, label) {
  const path = pathValue(value, label);
  if (/[\s#'"\\]/u.test(path)) {
    fail(`${label} must be a systemd EnvironmentFile-safe absolute path`);
  }
  return path;
}
function canonicalSource(path, label) {
  const absolute = pathValue(path, label);
  let source;
  try {
    source = readFileSync(absolute, "utf8");
  } catch (error) {
    fail(`${label} is unreadable: ${error.message}`);
  }
  let value;
  try {
    value = JSON.parse(source);
  } catch (error) {
    fail(`${label} is not JSON: ${error.message}`);
  }
  if (`${canonicalJson(value)}\n` !== source) {
    fail(`${label} is not canonical exact JSON bytes`);
  }
  return { absolute, source, value };
}
export function writeCreateOnly(path, value) {
  const absolute = pathValue(path, "output path"), parent = dirname(absolute);
  if (
    !existsSync(parent) || !lstatSync(parent).isDirectory() ||
    lstatSync(parent).isSymbolicLink()
  ) fail("output parent must be an existing real directory");
  if (existsSync(absolute)) {
    fail(`refusing to overwrite existing artifact: ${absolute}`);
  }
  const fd = openSync(absolute, "wx", 0o600);
  try {
    writeFileSync(
      fd,
      typeof value === "string" ? value : `${canonicalJson(value)}\n`,
      "utf8",
    );
  } finally {
    closeSync(fd);
  }
  return absolute;
}
export function validateTrustedKeyMap(keys) {
  exact(keys, Object.keys(keys ?? {}), "trusted public-key map");
  const entries = Object.entries(keys);
  if (entries.length === 0) fail("trusted public-key map must not be empty");
  for (const [keyId, encoded] of entries) {
    if (!identifier(keyId)) {
      fail("trusted public-key map contains an invalid key id");
    }
    strictPoint(b64(encoded, 32, "trusted public key"), "trusted public key");
  }
  return Object.freeze(
    Object.fromEntries(
      entries.sort(([left], [right]) =>
        left.localeCompare(right, "en", { sensitivity: "variant" })
      ),
    ),
  );
}
export function readTrustedKeyMap(path) {
  const { value } = canonicalSource(path, "trusted public-key map");
  return validateTrustedKeyMap(value);
}
function validateUnsignedEditorial(value) {
  exact(value, [
    "expiresAt",
    "grantId",
    "issuedAt",
    "issuerKeyId",
    "kind",
    "scope",
  ], "unsigned editorial grant");
  if (
    value.kind !== EDITORIAL_KIND || !identifier(value.grantId) ||
    !identifier(value.issuerKeyId) || !timestamp(value.issuedAt) ||
    !timestamp(value.expiresAt) ||
    Date.parse(value.expiresAt) <= Date.parse(value.issuedAt)
  ) fail("unsigned editorial grant identifiers or validity window are invalid");
  exact(value.scope, ["manuscript", "type"], "unsigned editorial grant scope");
  exact(
    value.scope.manuscript,
    ["digest", "slug"],
    "unsigned editorial manuscript",
  );
  if (
    value.scope.type !== "exact-manuscript" ||
    !slug(value.scope.manuscript.slug) || !sha256(value.scope.manuscript.digest)
  ) fail("unsigned editorial grant must have an exact manuscript scope");
}
function validateUnsignedRelease(value) {
  exact(value, [
    "admission",
    "expiresAt",
    "grantId",
    "issuedAt",
    "issuerKeyId",
    "kind",
    "scope",
  ], "unsigned Cloudflare grant");
  if (
    value.kind !== RELEASE_KIND || !identifier(value.grantId) ||
    !identifier(value.issuerKeyId) || !timestamp(value.issuedAt) ||
    !timestamp(value.expiresAt) ||
    Date.parse(value.expiresAt) <= Date.parse(value.issuedAt)
  ) {
    fail(
      "unsigned Cloudflare grant identifiers or validity window are invalid",
    );
  }
  exact(
    value.admission,
    ["kind", "verifiedProviderAuthority"],
    "unsigned Cloudflare grant admission",
  );
  if (
    value.admission.kind !== "local-operator-admission" ||
    value.admission.verifiedProviderAuthority !== false
  ) {
    fail(
      "unsigned Cloudflare grant must state its local operator admission limit",
    );
  }
  exact(
    value.scope,
    value.scope.action === "release"
      ? [
        "action",
        "baselineManifestSha256",
        "bindingSha256",
        "candidateManifestSha256",
        "target",
      ]
      : ["action", "bindingSha256", "candidateManifestSha256", "target"],
    "unsigned Cloudflare grant scope",
  );
  if (
    !["preview", "release"].includes(value.scope.action) ||
    !rawSha256(value.scope.bindingSha256) ||
    !rawSha256(value.scope.candidateManifestSha256) ||
    (value.scope.action === "release" &&
      !rawSha256(value.scope.baselineManifestSha256))
  ) fail("unsigned Cloudflare grant action or digests are invalid");
  exact(
    value.scope.target,
    Object.keys(TARGET),
    "unsigned Cloudflare grant target",
  );
  for (const [key, expected] of Object.entries(TARGET)) {
    if (value.scope.target[key] !== expected) {
      fail(`unsigned Cloudflare grant target.${key} is invalid`);
    }
  }
}
function validateUnsigned(kind, value) {
  if (!object(value) || Object.hasOwn(value, "signature")) {
    fail("unsigned artifact must be a plain object with no signature member");
  }
  if (kind === "editorial") return validateUnsignedEditorial(value);
  if (kind === "cloudflare") return validateUnsignedRelease(value);
  fail("kind must be editorial or cloudflare");
}
export function formEditorialGrant(
  { draftPath, manuscriptSlug, grantId, issuerKeyId, issuedAt, expiresAt },
) {
  const draft = pathValue(draftPath, "draft path");
  let bytes;
  try {
    if (lstatSync(draft).isSymbolicLink() || !lstatSync(draft).isFile()) {
      fail("draft path must be a real regular file");
    }
    bytes = readFileSync(draft);
  } catch (error) {
    if (error instanceof TypeError) throw error;
    fail(`draft path is unreadable: ${error.message}`);
  }
  const unsigned = {
    expiresAt,
    grantId,
    issuedAt,
    issuerKeyId,
    kind: EDITORIAL_KIND,
    scope: {
      manuscript: { digest: sha256Digest(bytes), slug: manuscriptSlug },
      type: "exact-manuscript",
    },
  };
  validateUnsignedEditorial(unsigned);
  return Object.freeze(unsigned);
}
export function formFirstPostHandoff({ draftPath, manuscriptSlug }) {
  const draft = pathValue(draftPath, "draft path");
  let bytes;
  try {
    if (lstatSync(draft).isSymbolicLink() || !lstatSync(draft).isFile()) {
      fail("draft path must be a real regular file");
    }
    bytes = readFileSync(draft);
  } catch (error) {
    if (error instanceof TypeError) throw error;
    fail(`draft path is unreadable: ${error.message}`);
  }
  const source = bytes.toString("utf8");
  const frontMatter = /^---\n([\s\S]*?)\n---\n/u.exec(source)?.[1];
  if (!frontMatter || !/^draft: true$/mu.test(frontMatter)) {
    fail("draft must retain an exact front-matter draft: true state");
  }
  if (!slug(manuscriptSlug)) fail("manuscript slug is invalid");
  const declaredSlug = /^slug:\s*(?:"([^"]+)"|'([^']+)'|([^\s#]+))\s*$/mu.exec(
    frontMatter,
  );
  const frontMatterSlug = declaredSlug?.[1] ?? declaredSlug?.[2] ??
    declaredSlug?.[3];
  if (frontMatterSlug !== manuscriptSlug) {
    fail("draft front-matter slug must exactly match manuscript slug");
  }
  return Object.freeze({
    boundaries: Object.freeze({
      delivery: "not-prepared",
      editorialAdmission:
        "required: exact current editorial-judgments acceptance record copied without interpretation",
      publicationGrant:
        "required: externally supplied signed exact-manuscript grant and independently configured public-key map",
    }),
    kind: "koios.news.first-post-handoff/v1",
    manuscript: Object.freeze({
      bytes: bytes.length,
      digest: sha256Digest(bytes),
      requiredSourceState: "draft: true",
      slug: manuscriptSlug,
    }),
    status: "inert-preparation-only",
  });
}
export function formCloudflareGrant(
  {
    candidateDir,
    bindingPath,
    action,
    grantId,
    issuerKeyId,
    issuedAt,
    expiresAt,
    productionBaselinePath,
  },
) {
  const candidate = verifyCandidate(candidateDir),
    binding = verifyBinding(bindingPath);
  const baseline = action === "release"
    ? verifyProductionBaseline(productionBaselinePath, candidate)
    : undefined;
  const unsigned = {
    admission: {
      kind: "local-operator-admission",
      verifiedProviderAuthority: false,
    },
    expiresAt,
    grantId,
    issuedAt,
    issuerKeyId,
    kind: RELEASE_KIND,
    scope: {
      action,
      ...(action === "release"
        ? { baselineManifestSha256: baseline.manifestSha256 }
        : {}),
      bindingSha256: binding.digest,
      candidateManifestSha256: candidate.manifestDigest,
      target: TARGET,
    },
  };
  validateUnsignedRelease(unsigned);
  return Object.freeze(unsigned);
}
/**
 * Form the local rollback binding consumed by koios-news-cloudflare-release-engine.
 * It does not contact Cloudflare, inspect credentials, sign, or execute a rollback.
 */
export function formCloudflareRollbackBinding({ bindingPath, priorVersionId }) {
  const binding = verifyBinding(bindingPath);
  if (typeof priorVersionId !== "string" || priorVersionId.length < 1) {
    fail("rollback.priorVersionId is required");
  }
  return Object.freeze({
    bindingSha256: binding.digest,
    kind: "koios.news.cloudflare-rollback-binding/v1",
    ...TARGET,
    priorVersionId,
  });
}
export function attachExternalSignature(
  { kind, unsignedPath, signature, authorityKeysPath },
) {
  const { value } = canonicalSource(unsignedPath, "unsigned artifact");
  validateUnsigned(kind, value);
  const keys = readTrustedKeyMap(authorityKeysPath),
    publicEncoded = keys[value.issuerKeyId];
  if (publicEncoded === undefined) {
    fail(
      "issuer key id is not present in the independently configured trusted-key map",
    );
  }
  const publicKey = b64(publicEncoded, 32, "trusted public key"),
    signatureBytes = b64(signature, 64, "external signature");
  strictPoint(publicKey, "trusted public key");
  strictPoint(signatureBytes.subarray(0, 32), "external signature R");
  if (littleEndian(signatureBytes.subarray(32)) >= ED25519_ORDER) {
    fail("external signature scalar is noncanonical");
  }
  const key = createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, publicKey]),
    format: "der",
    type: "spki",
  });
  if (
    !verify(
      null,
      Buffer.from(canonicalJson(value), "utf8"),
      key,
      signatureBytes,
    )
  ) {
    fail(
      "external signature does not verify against the unsigned exact bytes and configured public key",
    );
  }
  return Object.freeze({ ...value, signature });
}
export function verifyEditorialArtifact(
  { grantPath, authorityKeysPath, draftPath, manuscriptSlug, now },
) {
  const grantSource = canonicalSource(grantPath, "signed editorial grant");
  const authorityKeys = readTrustedKeyMap(authorityKeysPath);
  const draft = pathValue(draftPath, "draft path");
  const manuscriptSource = readFileSync(draft, "utf8");
  return verifyPublicationAuthority({
    grantSource: grantSource.source,
    authorityKeys,
    manuscriptSource,
    manuscriptSlug,
    now,
  });
}
/**
 * Verify a completed Cloudflare grant before any effecting carrier command.
 * This reads only the sealed inputs and has no replay, credential, or network
 * side effect.
 */
export function verifyCloudflareArtifact(
  {
    grantPath,
    authorityKeysPath,
    candidateDir,
    bindingPath,
    action,
    now,
    productionBaselinePath,
  },
) {
  if (!["preview", "release"].includes(action)) {
    fail("Cloudflare verification action must be preview or release");
  }
  const candidate = verifyCandidate(candidateDir);
  const binding = verifyBinding(bindingPath);
  const baseline = action === "release"
    ? verifyProductionBaseline(productionBaselinePath, candidate)
    : undefined;
  return verifyGrant(
    pathValue(grantPath, "Cloudflare grant path"),
    pathValue(authorityKeysPath, "authority key map path"),
    candidate,
    binding,
    action,
    now,
    baseline,
  );
}
function routineEnvironmentNames() {
  let config;
  try {
    config = JSON.parse(
      readFileSync(
        // The routine-operation contract is the koios.news site's: its data root (SECTION_DATA_ROOT, default the
        // working directory, where the site runs this tool) holds config/routine-operation.json.
        resolve(process.env.SECTION_DATA_ROOT ?? process.cwd(), "config/routine-operation.json"),
        "utf8",
      ),
    );
  } catch (error) {
    fail(`current routine-operation config is unreadable: ${error.message}`);
  }
  const fields = [
    "jobEnvironment",
    "queueEnvironment",
    "authorityKeysEnvironment",
    "assessmentKeysEnvironment",
    "outputRootEnvironment",
    "replayRootEnvironment",
    "propertyEnvironment",
  ];
  if (
    !object(config) || config.contract !== "koios-news/routine-operation/v1" ||
    Object.keys(config).length !== fields.length + 1 ||
    fields.some((field) =>
      typeof config[field] !== "string" ||
      !/^[A-Z][A-Z0-9_]*$/u.test(config[field])
    )
  ) {
    fail(
      "current routine-operation config has an invalid environment contract",
    );
  }
  return Object.freeze(fields.map((field) => config[field]));
}
const ENVIRONMENT_NAMES = routineEnvironmentNames();
export function formRoutineEnvironment(values) {
  const shared = ENVIRONMENT_NAMES.filter((name) => !["KOIOS_NEWS_ROUTINE_PUBLICATION_JOB", "KOIOS_NEWS_ROUTINE_PUBLICATION_QUEUE"].includes(name));
  const selected = ["KOIOS_NEWS_ROUTINE_PUBLICATION_JOB", "KOIOS_NEWS_ROUTINE_PUBLICATION_QUEUE"].filter((name) => Object.hasOwn(values, name));
  if (!object(values) || selected.length !== 1 || Object.keys(values).length !== shared.length + 1 || [...shared, ...selected].some((name) => !Object.hasOwn(values, name))) fail("routine environment requires exactly one job or queue path");
  return `${
    [...selected, ...shared].map((name) =>
      `${name}=${environmentPath(values[name], name)}`
    ).join("\n")
  }\n`;
}
export function summarizeArtifact(kind, value) {
  return kind === "cloudflare"
    ? {
      kind: value.kind,
      grantId: value.grantId,
      action: value.scope.action,
      candidateManifestSha256: value.scope.candidateManifestSha256,
      bindingSha256: value.scope.bindingSha256,
      unsignedSha256: sha256Hex(Buffer.from(canonicalJson(value), "utf8")),
    }
    : {
      kind: value.kind,
      grantId: value.grantId,
      manuscript: value.scope.manuscript,
      unsignedSha256: sha256Digest(Buffer.from(canonicalJson(value), "utf8")),
    };
}
