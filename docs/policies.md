# Writing & Testing Policies

Custodian evaluates rules written in **YAML** using **CEL (Common Expression Language)**. You can validate, simulate, and unit-test policy bundles completely offline with `custodian-policy`.

## Included Policies

- [policies/defaults/default.yaml](../policies/defaults/default.yaml) — Default organization baseline for workspace `INGRESS` and proposal `EGRESS`
- [policies/defaults/push-ip-protection.yaml](../policies/defaults/push-ip-protection.yaml) — Default organization rules for `PUSH_EGRESS` (secrets, licenses, IP fingerprints, concealment, and unregistered destinations)
- [policies/examples/](../policies/examples/) — Sample `ORG` and `REPO` bundles you can adapt
- [policies/tests/](../policies/tests/) — YAML test suites verifying policy behavior

## PolicyBundle Structure

```yaml
apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: repo-strict-security
  version: "1.0.0"
  scope: REPO # ORG or REPO
defaults:
  effect: DENY
  onError: DENY
inspection:
  mandatory:
    - gitleaks
    - scancode
    - semgrep
    - trivy
  decisionModel:
    route: approved-code-review
    trigger:
      - high_risk_change
rules:
  - id: repo.security.auth_paths
    description: Require two security-team reviewers when auth or security files change.
    stages: [EGRESS]
    when: change.paths.exists(p, p.startsWith("auth/") || p.startsWith("security/"))
    effect: REQUIRE_APPROVAL
    obligations:
      - type: HUMAN_REVIEW
        reviewer_group: security-team
        minimum: 2
    message: Changes under auth/ or security/ require two security-team approvals.
```

## Stages

Every rule specifies which stage(s) it applies to in `stages`:

- `INGRESS` — Evaluated before source is delivered to a workspace.
- `EGRESS` — Evaluated on a Change Proposal before human approval and PR publication.
- `PUSH_EGRESS` — Evaluated on a `git push` through `custodian-git-gateway`.

## Effects & Precedence (Most Restrictive Wins)

When multiple rules match, Custodian always applies the **most restrictive** effect. If a rule fails to evaluate or no rules match, `defaults.onError` / `defaults.effect` applies (defaulting to fail-closed `DENY`):

1. `DENY` *(most restrictive)* — Hard block.
2. `QUARANTINE` — Hold for security investigation (for example, incomplete scans or concealed payloads).
3. `REQUIRE_REMEDIATION` — Author must fix issues and resubmit before approval.
4. `REQUIRE_APPROVAL` — Requires human review (with optional `obligations` specifying `reviewer_group` and `minimum` approvals).
5. `ALLOW` *(least restrictive)* — Permits proceeding.

## Organization vs. Repository Composition

When both an `ORG` bundle and a `REPO` bundle are evaluated:

- `ORG` rules run first and default to `overridable: false`.
- A `REPO` bundle can **never weaken** an `ORG` decision—it can only keep the same restrictiveness or make it stricter (for example, requiring more reviewers or blocking additional paths).

## Available CEL Variables

| Variable | Common Fields |
| :--- | :--- |
| `findings` | `scan_complete`, `mandatory_scanners_complete`, `critical_secrets`, `prohibited_licenses`, `high_vulnerabilities`, `high_sast_findings`, `total_findings`, `restricted_ip_matches`, `confidential_ip_matches`, `ip_exact_matches`, `ip_winnow_matches`, `ip_header_strip_matches`, `concealment_findings`, `failed_scanners`, `incomplete_scanners` |
| `assessment` | `status` (`COMPLETE`, `NOT_REQUIRED`, `INDETERMINATE`, `FAILED`), `disposition` (`CLEAR`, `REVIEW`, `ESCALATE`, `BLOCK`, `INDETERMINATE`, `NOT_REQUIRED`), `risk`, `ip_risk`, `assessment_type`, `model_route` |
| `change` | `paths` (list of changed file paths), `file_count`, `total_bytes`, `tree_digest`, `diff_digest`, `manifest_digest`, `base_commit`, `target_ref` |
| `repository` | `id`, `full_name`, `classification` (`PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`), `enabled`, `allowed_model_routes` |
| `workspace` | `id`, `generation`, `agent_assisted`, `model_route`, `include_git_metadata`, `include_history` |
| `proposal` | `id`, `version`, `owner_id`, `provenance_type`, `capture_method` |
| `principal` | `id`, `kind`, `subject`, `display_name`, `verified_email`, `groups`, `roles` |
| `provenance` | `type`, `capture_method` |
| `destination` | `id`, `name`, `host`, `registered`, `external`, `classification`, `org`, `owner` |
| `push` | `has_lfs`, `lfs_object_count`, `lfs_total_bytes`, `ref_names`, `commit_count`, `egress_mode`, `approval_release_present`, `push_manifest_digest` |
| `stage` | Current evaluation stage string (`"INGRESS"`, `"EGRESS"`, or `"PUSH_EGRESS"`) |
| `flags` | Map of boolean feature flags |

## Testing Policies Offline with `custodian-policy`

Validate syntax and compile all CEL expressions in a bundle:

```sh
./bin/custodian-policy validate --bundle policies/defaults/default.yaml
```

Simulate a bundle (optionally composed with an org bundle) against a JSON input file:

```sh
./bin/custodian-policy evaluate \
  --org-bundle policies/examples/org_baseline.yaml \
  --bundle policies/examples/repo_strict_security.yaml \
  --input input.json \
  --stage EGRESS \
  --format text
```

Run all YAML `PolicyTestSuite` files in a directory:

```sh
./bin/custodian-policy test policies/tests
```

You can also validate and simulate policies against a running API server with `custodian policies validate` and `custodian policies evaluate`.
