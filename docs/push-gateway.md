# Git Push Gateway

`custodian-git-gateway` sits in front of your upstream Git remote (such as GitHub) and inspects every `git push` over **HTTPS** or **SSH** before any bytes are forwarded upstream.

It protects against accidental pushes of secrets, prohibited licenses, obfuscated payloads, and proprietary source code—even when developers push directly from local laptops rather than through brokered workspaces.

## How a Push Flows Through the Gateway

1. **Authenticate**: The developer pushes over HTTPS (using an OIDC token via `custodian credential-helper`) or SSH (using a short-lived SSH user certificate signed by your SSH User CA). Any forged Git `Author`/`Committer` metadata inside the commits is ignored for identity attribution.
2. **Quarantine & Unpack**: Incoming packfiles (and Git LFS pointers) are unpacked inside an isolated quarantine directory with strict caps on pack size, object count, inflated object size, and ref updates.
3. **Inspect**: Custodian runs automated scanners (`gitleaks`, `scancode`, `semgrep`), proprietary IP fingerprinting, concealment/smuggling detection (such as stripped copyright headers, encoded secrets, or nested archives), and optional AI risk review.
4. **Enforce Policy**: The `PUSH_EGRESS` CEL policy rules (see [policies/defaults/push-ip-protection.yaml](../policies/defaults/push-ip-protection.yaml)) decide the outcome:
   - `ALLOW` — Forward the push to the upstream remote.
   - `REQUIRE_APPROVAL` — Hold the push (`APPROVAL_REQUIRED`) until a separate reviewer issues a single-use release. Zero bytes are sent upstream.
   - `DENY` / `QUARANTINE` — Block the push (`BLOCKED` / `QUARANTINED`) and report the reason over the Git push output. Zero bytes are sent upstream.

## Safe Rollout Modes

You can set a default mode on the gateway (`CUSTODIAN_GIT_GATEWAY_DEFAULT_EGRESS_MODE`) and override it per repository via `PUT /v1/repositories/{id}/egress-mode`:

| Mode | Behavior | Best For |
| :--- | :--- | :--- |
| `PASSIVE_AUDIT` | Forwards pushes upstream while recording what *would* have been blocked (`OBSERVED_WOULD_BLOCK`). Set `passive_audit_delivery` to `INLINE_WARN` to print warnings in `git push` output, or `ASYNC` to log silently. | Rolling out Custodian safely without interrupting teams |
| `ENFORCE_BLOCK` | Enforces policies strictly. Blocked, quarantined, or unapproved pushes never send bytes upstream. | Production protection against secrets and IP leaks |
| `ENFORCE_PR` | Routes pushes into Custodian's pull-request review workflow instead of pushing directly to upstream branches. | Repositories requiring PR-only changes |

Example: switch a repository to `PASSIVE_AUDIT` with inline warnings and mark it as a registered internal destination:

```sh
curl -X PUT "$CUSTODIAN_API_URL/v1/repositories/<repo-uuid>/egress-mode" \
  -H "Authorization: Bearer $CUSTODIAN_TOKEN" \
  -H "Idempotency-Key: set-mode-01" \
  -H "Content-Type: application/json" \
  -d '{
    "egress_mode": "PASSIVE_AUDIT",
    "passive_audit_delivery": "INLINE_WARN",
    "registered_destination": true,
    "external": false
  }'
```

## Connecting Git Clients

### HTTPS with `custodian credential-helper`

`custodian` includes a built-in Git credential helper that verifies your OIDC token against `custodian-api` and supplies credentials to Git without ever writing tokens to plaintext files (`store` and `erase` are no-ops):

```sh
export CUSTODIAN_API_URL="http://127.0.0.1:8080"
export CUSTODIAN_TOKEN_FILE="/path/to/oidc-jwt.txt"

git config credential.helper ""
git config --add credential.helper \
  "!custodian credential-helper --api-url $CUSTODIAN_API_URL --allowed-hosts gateway.example.com"
```

Then push to your gateway remote:

```sh
git push https://gateway.example.com:8443/your-org/your-repo.git main
```

### SSH with User Certificates

Configure `custodian-git-gateway` with `CUSTODIAN_GIT_GATEWAY_SSH_HOST_KEY_FILE` and `CUSTODIAN_GIT_GATEWAY_SSH_USER_CA_FILE`. Developers authenticate using short-lived OpenSSH user certificates signed by that CA and push normally:

```sh
git push ssh://git@gateway.example.com:2222/your-org/your-repo.git main
```

## Checking Push Status & Approving Held Pushes

Check your recent pushes or inspect a specific push session in human-readable text or JSON:

```sh
# List recent push sessions
custodian push status --format text

# Filter by status or repository
custodian push status --status APPROVAL_REQUIRED --limit 20 --format text

# Inspect a specific push session and next steps
custodian push status <push-session-id> --format text
```

When a push is in `APPROVAL_REQUIRED`, a **different** authorized reviewer (separation of duties prevents self-approval) issues a single-use, expiring approval release bound to the exact `push_manifest_digest`, destination, and caller:

```sh
curl -X POST "$CUSTODIAN_API_URL/v1/pushes/<push-session-id>/approvals" \
  -H "Authorization: Bearer $REVIEWER_TOKEN" \
  -H "Idempotency-Key: approve-push-01" \
  -H "Content-Type: application/json" \
  -d '{
    "decision": "APPROVE",
    "push_manifest_digest": "<push_manifest_digest>",
    "ttl_seconds": 900,
    "comment": "Verified benign match; allow one-time push."
  }'
```

Once approved, the developer simply re-runs `git push`.

## Proprietary IP Fingerprinting (`IP Corpora`)

To prevent proprietary source code from being copied into public or external repositories, register your `CONFIDENTIAL` or `RESTRICTED` repositories as IP fingerprint corpora:

- `POST /v1/ip-corpora` — Register a corpus (`CONFIDENTIAL` or `RESTRICTED`)
- `POST /v1/ip-corpora/{id}/reindex` — Build fingerprints from source files
- `GET /v1/ip-corpora` — List registered corpora

Custodian indexes three complementary layers while storing **only one-way hashes and metadata—never raw source code**:

1. **`L1_EXACT_CHUNK`** — Detects verbatim copied blocks of code.
2. **`L2_WINNOW_KGRAM`** — Uses Winnowing k-gram fingerprints to catch code even after formatting edits or variable renames.
3. **`L3_HEADER_MARKER`** — Detects proprietary copyright or confidentiality markers, including attempts to strip headers before pushing.
