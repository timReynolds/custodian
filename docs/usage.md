# Workspace & Pull Request Workflow

This guide walks through Custodian's brokered workflow using the `custodian` CLI: checking out a credentialless workspace, submitting changes, running inspection and policy checks, approving by content digest, and opening a pull request.

## CLI Setup

Point the `custodian` CLI at your API server and provide an OIDC bearer token:

```sh
export CUSTODIAN_API_URL="http://127.0.0.1:8080"
export CUSTODIAN_TOKEN_FILE="/path/to/oidc-jwt.txt"
# Or pass directly: export CUSTODIAN_TOKEN="<jwt>"
```

Check that the API is alive and connected to PostgreSQL:

```sh
custodian health
custodian ready
```

> **Note on idempotency:** The `custodian` CLI automatically adds an `Idempotency-Key` header on mutating requests (and lets you pass `--idempotency-key` explicitly). If you call the REST API directly, include `Idempotency-Key` on all mutating `POST` and `PUT` endpoints as specified in [api/openapi.yaml](../api/openapi.yaml).

## 1. Create a Credentialless Workspace

Create a workspace pinned to a GitHub repository ID and ref (branch, tag, or commit SHA). Custodian establishes the accountable human owner from your verified OIDC token—never from request parameters.

If a coding agent will work in the workspace, include the `--agent-type`, `--agent-session`, and `--model-route` flags so agent provenance is tracked separately from human ownership:

```sh
custodian workspaces create \
  --repo-id 12345678 \
  --ref main \
  --agent-type coding-agent \
  --agent-session session-01 \
  --model-route approved-code-review
```

Optional flags:
- `--include-git-metadata` — Include sanitized `.git` metadata (without remotes or credentials)
- `--include-history` — Include commit history

The response includes a `workspace_id` and an `operation_id`. Poll the operation until it finishes:

```sh
custodian operations get <operation-id>
custodian workspaces get <workspace-id>
```

## 2. Download Clean Source & Upload Changes

Once the workspace status is `READY`, fetch its source descriptor:

```sh
custodian workspaces source <workspace-id>
```

This returns:
- A clean, credentialless source archive reference (containing no tokens, SSH keys, or credential helpers).
- A short-lived, HMAC-signed `upload_capability` URL (`PUT /v1/uploads/workspaces/{id}/generations/{generation}/...`) scoped exclusively to uploading a frozen workspace archive back to Custodian.

After the human or agent finishes editing in the isolated sandbox, package the workspace directory as a `.tar.gz` archive, compute its SHA-256 hex digest, and `PUT` it to the signed upload capability URL (which returns the `artifact_id`).

## 3. Submit a Change Proposal

Register the uploaded snapshot as a Change Proposal:

```sh
custodian proposals submit <workspace-id> \
  --artifact-id <artifact-uuid> \
  --sha256 <sha256-hex> \
  --generation 1 \
  --title "Add input validation for config loader" \
  --provenance-type agent_assisted \
  --capture-method frozen_filesystem
```

Custodian reconstructs the snapshot against the pinned base commit in a clean server-side checkout and produces a canonical diff and `publication_manifest_digest`.

## 4. Inspect Diff, Findings & Run Policies

Review the reconstructed diff, trigger the three-stage evaluation (automated scanners, optional AI review, CEL policy rules), and inspect the results:

```sh
# View the canonical diff and publication_manifest_digest
custodian proposals diff <proposal-id>

# Run Stage A scanners, Stage B model review (if triggered), and Stage C CEL policies
custodian proposals evaluate <proposal-id>

# Inspect redacted scanner findings (optional filters: --scanner, --severity, --limit)
custodian proposals findings <proposal-id>

# Inspect model assessments and policy decision (including policy_evaluation_id)
custodian proposals assessments <proposal-id>
```

You can also inspect current proposal state at any time with `custodian proposals get <proposal-id>`.

## 5. Approve by Exact Digest

To approve (or reject) a proposal, a human reviewer binds their decision to both the exact `publication_manifest_digest` and the `policy_evaluation_id` from the previous step. If anything in the proposal changes, the digest no longer matches and approval fails:

```sh
custodian proposals approve <proposal-id> \
  --decision APPROVE \
  --manifest-digest <publication-manifest-digest> \
  --policy-evaluation-id <policy-evaluation-id> \
  --comment "Reviewed diff and scanner findings."
```

## 6. Publish the Pull Request

Trigger `custodian-publisher` to create a single commit and open a PR on `custodian/<proposal-id>`:

```sh
custodian proposals publish <proposal-id> \
  --manifest-digest <publication-manifest-digest>

# Poll publication progress and PR URL/number
custodian publications get <publication-id>
```

The published commit attributes the verified human owner as Git `Author`, `Custodian` as `Committer`, and appends provenance trailers:

```text
Custodian-Proposal: <proposal-id>
Custodian-Workspace: <workspace-id>
Agent-Assisted: true
```

## 7. Query the Audit Trail

Every action in the lifecycle is written to a hash-chained `audit_events` log:

```sh
custodian audit list --resource-type proposal --resource-id <proposal-id>
```
