package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/policy"
)

func (s *server) handleValidatePolicy(w http.ResponseWriter, r *http.Request) {
	caller, ok := CallerFromContext(r.Context())
	if !ok {
		writeError(w, r, s.deps.Logger, domain.Unauthorized("UNAUTHORIZED", "authentication required"))
		return
	}
	if !caller.IsPolicyAdmin() {
		writeError(w, r, s.deps.Logger, domain.Forbidden("POLICY_ADMIN_REQUIRED", "only POLICY_ADMIN principals may validate policy bundles"))
		return
	}
	if s.deps.PolicyEngine == nil {
		writeError(w, r, s.deps.Logger, domain.Unavailable("SERVICE_UNAVAILABLE", "policy engine is not configured"))
		return
	}
	if _, err := parseIdempotencyKeyHeader(r, false); err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	rawBody, err := readBoundedBody(w, r, maxJSONBodyBytes)
	if err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	var req ValidatePolicyRequest
	if err := decodeStrictJSONBytes(rawBody, &req, false); err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}
	if len(strings.TrimSpace(req.BundleYAML)) == 0 {
		writeError(w, r, s.deps.Logger, domain.BadRequest("INVALID_BUNDLE_YAML", "bundle_yaml must not be empty"))
		return
	}

	var res policy.ValidationResult
	if req.TestCasesYAML != nil && len(strings.TrimSpace(*req.TestCasesYAML)) > 0 {
		res, _ = s.deps.PolicyEngine.ValidateWithTests(r.Context(), []byte(req.BundleYAML), []byte(*req.TestCasesYAML))
	} else {
		res = s.deps.PolicyEngine.Validate([]byte(req.BundleYAML))
	}

	writeJSON(w, http.StatusOK, toValidatePolicyResponse(res))
}

func (s *server) handleEvaluatePolicy(w http.ResponseWriter, r *http.Request) {
	caller, ok := CallerFromContext(r.Context())
	if !ok {
		writeError(w, r, s.deps.Logger, domain.Unauthorized("UNAUTHORIZED", "authentication required"))
		return
	}
	if !caller.IsPolicyAdmin() {
		writeError(w, r, s.deps.Logger, domain.Forbidden("POLICY_ADMIN_REQUIRED", "only POLICY_ADMIN principals may simulate policy evaluation"))
		return
	}
	if s.deps.PolicyEngine == nil {
		writeError(w, r, s.deps.Logger, domain.Unavailable("SERVICE_UNAVAILABLE", "policy engine is not configured"))
		return
	}
	if _, err := parseIdempotencyKeyHeader(r, false); err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	rawBody, err := readBoundedBody(w, r, maxJSONBodyBytes)
	if err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	var req SimulatePolicyRequest
	if err := decodeStrictJSONBytes(rawBody, &req, false, "input"); err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}
	if !policy.IsValidStage(req.Stage) {
		writeError(w, r, s.deps.Logger, domain.BadRequest("INVALID_POLICY_STAGE", "stage must be INGRESS, EGRESS, or PUSH_EGRESS"))
		return
	}
	if req.Input == nil {
		writeError(w, r, s.deps.Logger, domain.BadRequest("INVALID_POLICY_INPUT", "input object is required"))
		return
	}

	var repoBundle, orgBundle *policy.CompiledBundle

	if req.BundleYAML != nil {
		if strings.TrimSpace(*req.BundleYAML) == "" {
			writeError(w, r, s.deps.Logger, domain.BadRequest("INVALID_BUNDLE_YAML", "bundle_yaml must not be empty when provided"))
			return
		}
		cb, errs := s.deps.PolicyEngine.Compile([]byte(*req.BundleYAML))
		if len(errs) > 0 {
			writeError(w, r, s.deps.Logger, domain.Unprocessable("INVALID_POLICY_BUNDLE", fmt.Sprintf("bundle_yaml compilation failed: [%s] %s", errs[0].Code, errs[0].Message)))
			return
		}
		repoBundle = cb
	} else if req.BundleID != nil {
		bundleID, err := parseUUIDv7(*req.BundleID)
		if err != nil {
			writeError(w, r, s.deps.Logger, err)
			return
		}
		if s.deps.Store == nil {
			writeError(w, r, s.deps.Logger, domain.Unavailable("SERVICE_UNAVAILABLE", "persistence store is not configured"))
			return
		}
		dbCtx, cancel := s.withDBTimeout(r.Context())
		row, err := s.deps.Store.GetPolicyBundleByID(dbCtx, bundleID)
		cancel()
		if err != nil {
			writeError(w, r, s.deps.Logger, mapDBTimeoutError(dbCtx, err))
			return
		}
		cb, errs := s.deps.PolicyEngine.CompileDomainBundle(row.ToDomain())
		if len(errs) > 0 {
			writeError(w, r, s.deps.Logger, domain.Unprocessable("INVALID_POLICY_BUNDLE", fmt.Sprintf("persisted bundle compilation failed: [%s] %s", errs[0].Code, errs[0].Message)))
			return
		}
		repoBundle = cb
	}

	if req.OrgBundleYAML != nil {
		if strings.TrimSpace(*req.OrgBundleYAML) == "" {
			writeError(w, r, s.deps.Logger, domain.BadRequest("INVALID_ORG_BUNDLE_YAML", "org_bundle_yaml must not be empty when provided"))
			return
		}
		cb, errs := s.deps.PolicyEngine.Compile([]byte(*req.OrgBundleYAML))
		if len(errs) > 0 {
			writeError(w, r, s.deps.Logger, domain.Unprocessable("INVALID_POLICY_BUNDLE", fmt.Sprintf("org_bundle_yaml compilation failed: [%s] %s", errs[0].Code, errs[0].Message)))
			return
		}
		orgBundle = cb
	}

	if repoBundle == nil && orgBundle == nil {
		writeError(w, r, s.deps.Logger, domain.BadRequest("MISSING_POLICY_BUNDLE", "bundle_yaml, org_bundle_yaml, or bundle_id is required"))
		return
	}

	var evalRes policy.EvalResult
	switch {
	case orgBundle != nil && repoBundle != nil:
		evalRes, err = s.deps.PolicyEngine.ComposeAndEvaluate(r.Context(), orgBundle, repoBundle, req.Stage, req.Input)
	case orgBundle != nil:
		evalRes, err = s.deps.PolicyEngine.Evaluate(r.Context(), orgBundle, req.Stage, req.Input)
	default:
		evalRes, err = s.deps.PolicyEngine.Evaluate(r.Context(), repoBundle, req.Stage, req.Input)
	}
	if err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	writeJSON(w, http.StatusOK, toSimulatePolicyResponse(evalRes))
}
