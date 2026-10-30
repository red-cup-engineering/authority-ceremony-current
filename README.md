# Koios news authority ceremony engine

<!-- 561-group-standards:badges:start -->
[![Causeway Services](https://img.shields.io/badge/561%20Group-Causeway%20Services-115e69)](https://github.com/causeway-services)
[![License: 561 Group 1.0](https://img.shields.io/badge/license-561%20Group%201.0-115e69)](LICENSE)
[![Indigenous data: CARE](https://img.shields.io/badge/Indigenous%20data-CARE-4b6f44)](https://github.com/causeway-services/.github/blob/main/GOVERNANCE.md)
[![Tips welcome](https://img.shields.io/badge/tips-welcome-d4a017)](https://github.com/561-group/.github/blob/main/TIPS.md)
<!-- 561-group-standards:badges:end -->

This offline app of computer-koios-news-media-systems-engineering-services-section prepares authority artifacts but never creates, imports, or
prints a private key. It never decides that a manuscript is publishable, edits
a draft, writes the runtime environment, invokes a scheduler, contacts
Cloudflare, or runs Wrangler.

An authority holder uses it in this order:

1. Create an unsigned grant. The JSON object bytes are
   taken to an independent signing device; the create-only artifact's terminal
   storage LF is not part of the signed message.
2. The signing device signs the object bytes exactly as written. It
   returns only the unpadded-base64url 64-byte Ed25519 signature.
3. Attach the returned signature against an independently configured public
   key map. The tool refuses weak Ed25519 encodings, an untrusted issuer, or a
   signature that does not verify the exact unsigned bytes.
4. Verify the finished editorial grant against the exact draft and explicit
   instant before installing it. The production routine repeats that check.

Every output is mode `0600`, create-only, and written only into an existing
non-symlink directory. Keep these authority and environment artifacts outside
the repository and outside any Cloudflare asset directory.

## Inert first-post handoff

`first-post-handoff` preserves the only repository-safe portion of a proposed
first-post ceremony: the exact current draft bytes, slug, and `draft: true`
precondition. It makes no claim about whether an editorial admission exists,
and it does not create a grant, key, signature, credential, candidate,
schedule, or delivery authority. Regenerate it when handing the exact draft to
an independent editor; do not check its output into the repository.

```sh
draft="$PWD/sites/koios.news/content/posts/reporting-source-1-for-living-memorial-palestinian-activist-alex.md"
node apps/koios-news-authority-ceremony-engine/bin/koios-news-authority-ceremony.mjs first-post-handoff \
  --draft "$draft" \
  --slug reporting-source-1-for-living-memorial-palestinian-activist-alex \
  --out /secure/koios-authority/alex-first-post-handoff.json
```

The resulting JSON names the exact digest and byte count and lists
only the separately supplied admission and signed-authority boundaries. The
ordinary `editorial-template`, `attach`, and `verify-editorial` sequence below
remains the only route to a signed editorial grant.

```sh
tool=apps/koios-news-authority-ceremony-engine/bin/koios-news-authority-ceremony.mjs

# This writes no signature and no private material.
node "$tool" editorial-template \
  --draft /secure/koios/posts/story.md --slug story \
  --grant-id 0123456789abcdef --issuer-key-id editorial-primary-20260829 \
  --issued-at 2026-08-29T12:00:00.000Z --expires-at 2026-08-29T13:00:00.000Z \
  --out /secure/authority/story.grant.unsigned.json

# The external signer returns SIGNATURE. The map contains only raw public keys:
# {"editorial-primary-20260829":"<32-byte-unpadded-base64url-public-key>"}
node "$tool" attach --kind editorial \
  --unsigned /secure/authority/story.grant.unsigned.json --signature "$SIGNATURE" \
  --authority-keys /secure/authority/editorial-public-keys.json \
  --out /secure/authority/story.grant.json

node "$tool" verify-editorial --grant /secure/authority/story.grant.json \
  --authority-keys /secure/authority/editorial-public-keys.json \
  --draft /secure/koios/posts/story.md --slug story --now 2026-08-29T12:05:00.000Z
```

`cloudflare-template` and `attach --kind cloudflare` use the same ceremony,
but form one action-specific (`preview` or `release`) grant from the sealed
candidate and exact release-binding bytes. A preview grant cannot release.
Release additionally requires `--production-baseline`: the exact observed live
legacy manifest bytes are hashed into the signed scope, and the candidate must
retain each baseline artifact path. Cloudflare grants are explicitly local
operator admissions with `verifiedProviderAuthority: false`, never a claim of
provider-side authority.

Before the separately authorized carrier command, use the no-effect verifier
against the exact sealed inputs. It checks the completed signature, explicit
validity window, action, target, candidate manifest, binding, and—only for a
release—the observed production baseline. It does not consume the grant,
contact Cloudflare, read credentials, create a replay record, or invoke
Wrangler.

```sh
node "$tool" verify-cloudflare \
  --grant /secure/authority/koios-preview.grant.json \
  --authority-keys /secure/authority/release-public-keys.json \
  --candidate /secure/koios/candidate/public \
  --binding cloudflare-release-current/content/koios-news-primary-binding.json \
  --action preview --now 2026-08-29T12:05:00.000Z
```

For `--action release`, also pass the exact `--production-baseline` file used
when the release grant was formed. A verified result is a handoff check, not
authorization to deploy; the effecting carrier still re-verifies and consumes
the grant before it invokes Wrangler.

## Inert rollback binding

After independently observing the current production version ID, form the
separate rollback binding from that explicit value and the exact release
binding file. This command only reads the binding and creates one
mode-`0600` file; it does not read credentials, contact Cloudflare, sign
anything, or execute a rollback. It verifies both the input binding and the
new output through `cloudflare-release-current`'s fixed-target contracts.

```sh
node apps/koios-news-authority-ceremony-engine/bin/koios-news-authority-ceremony.mjs rollback-binding \
  --binding /secure/koios/koios-news-primary-binding.json \
  --prior-version-id "$OBSERVED_PRIOR_VERSION_ID" \
  --out /secure/koios/koios-news-rollback-binding.json
```

Do not substitute a remembered or source-controlled version ID. Preserve the
observation separately; the generated artifact binds only the exact supplied
ID and exact binding-file bytes for a later, separately authorized release.

`routine-env` writes path-only environment entries. The only queue writer is
`formRoutineIssue`, which persists an independently assessed issue record and
its settled claim bundle before creating the queue file. For daily rotation,
place those create-only queue files in a read-only directory and use
`routine-env --queue /secure/koios/routine-jobs`. The routine reserves the
first bytewise queue entry for each ScheduleDelivery pulse in its durable
replay territory; a retry reuses the same immutable issue.
