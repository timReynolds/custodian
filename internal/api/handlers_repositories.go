package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/timreynolds/custodian/internal/audit"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/persistence"
)

func isCredentialUserinfo(userinfo string) bool {
	if strings.Contains(userinfo, ":") {
		return true
	}
	lower := strings.ToLower(strings.TrimSpace(userinfo))
	switch lower {
	case "x-access-token", "oauth2", "bearer", "basic", "token":
		return true
	}
	for _, prefix := range []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "glpat_", "github_pat_", "akia"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func validateRemoteHost(raw string) (string, error) {
	if utf8.RuneCountInString(raw) > 255 {
		return "", domain.BadRequest("INVALID_REMOTE_HOST", "remote_host must be between 1 and 255 characters")
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f || unicode.IsControl(r) {
			return "", domain.BadRequest("INVALID_REMOTE_HOST", "remote_host contains invalid control characters")
		}
	}
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	if trimmed == "" {
		return "", domain.BadRequest("INVALID_REMOTE_HOST", "remote_host must be between 1 and 255 characters")
	}
	for _, r := range trimmed {
		if unicode.IsSpace(r) {
			return "", domain.BadRequest("INVALID_REMOTE_HOST", "remote_host must not contain whitespace, slashes, or userinfo")
		}
	}
	if strings.ContainsAny(trimmed, "/\\@?#=") {
		return "", domain.BadRequest("INVALID_REMOTE_HOST", "remote_host must not contain whitespace, slashes, or userinfo")
	}
	return trimmed, nil
}

func validateGitRemoteURL(raw string) (string, error) {
	if utf8.RuneCountInString(raw) > 512 {
		return "", domain.BadRequest("INVALID_GIT_REMOTE_URL", "git_remote_url must be between 1 and 512 characters")
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f || unicode.IsControl(r) {
			return "", domain.BadRequest("INVALID_GIT_REMOTE_URL", "git_remote_url contains invalid control characters")
		}
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", domain.BadRequest("INVALID_GIT_REMOTE_URL", "git_remote_url must be between 1 and 512 characters")
	}
	if scrubAPISecretString(trimmed) != trimmed {
		return "", domain.BadRequest("INVALID_GIT_REMOTE_URL", "git_remote_url must not contain embedded credentials")
	}
	if strings.Contains(trimmed, "://") {
		u, err := url.Parse(trimmed)
		if err != nil || strings.TrimSpace(u.Host) == "" {
			return "", domain.BadRequest("INVALID_GIT_REMOTE_URL", "git_remote_url must be a valid URL")
		}
		if u.User != nil {
			if strings.EqualFold(u.Scheme, "http") || strings.EqualFold(u.Scheme, "https") {
				return "", domain.BadRequest("INVALID_GIT_REMOTE_URL", "git_remote_url must not contain embedded credentials")
			}
			if _, hasPass := u.User.Password(); hasPass || isCredentialUserinfo(u.User.Username()) {
				return "", domain.BadRequest("INVALID_GIT_REMOTE_URL", "git_remote_url must not contain embedded credentials")
			}
		}
		if u.RawQuery != "" {
			q, qErr := url.ParseQuery(u.RawQuery)
			if qErr != nil {
				return "", domain.BadRequest("INVALID_GIT_REMOTE_URL", "git_remote_url must not contain invalid query parameters")
			}
			for k := range q {
				if isSensitiveDestinationQueryKey(k) {
					return "", domain.BadRequest("INVALID_GIT_REMOTE_URL", "git_remote_url must not contain embedded credentials")
				}
			}
		}
		return trimmed, nil
	}
	baseAndQuery, _, _ := strings.Cut(trimmed, "#")
	if _, rawQuery, hasQuery := strings.Cut(baseAndQuery, "?"); hasQuery && hasSensitiveRawQuery(rawQuery) {
		return "", domain.BadRequest("INVALID_GIT_REMOTE_URL", "git_remote_url must not contain embedded credentials")
	}
	if userinfo, afterAt, hasAt := strings.Cut(trimmed, "@"); hasAt && !strings.ContainsAny(userinfo, "/?#") {
		if strings.TrimSpace(userinfo) == "" || strings.TrimSpace(afterAt) == "" {
			return "", domain.BadRequest("INVALID_GIT_REMOTE_URL", "git_remote_url must be a valid remote")
		}
		if isCredentialUserinfo(userinfo) {
			return "", domain.BadRequest("INVALID_GIT_REMOTE_URL", "git_remote_url must not contain embedded credentials")
		}
	}
	return trimmed, nil
}

func (s *server) handleSetRepositoryEgressMode(w http.ResponseWriter, r *http.Request) {
	caller, ok := CallerFromContext(r.Context())
	if !ok {
		writeError(w, r, s.deps.Logger, domain.Unauthorized("UNAUTHORIZED", "authentication required"))
		return
	}
	if !isPushAdmin(caller) {
		writeError(w, r, s.deps.Logger, domain.Forbidden("PUSH_ADMIN_REQUIRED", "only policy/security admins may configure repository egress mode"))
		return
	}
	if s.deps.Store == nil {
		writeError(w, r, s.deps.Logger, domain.Unavailable("STORE_UNAVAILABLE", "persistence store is not configured"))
		return
	}

	repoID, err := parseUUIDv7Param(r, "id")
	if err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	idemKey, err := parseIdempotencyKeyHeader(r, true)
	if err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	rawBody, err := readBoundedBody(w, r, maxJSONBodyBytes)
	if err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	var req SetRepositoryEgressModeRequest
	if err := decodeStrictJSONBytes(rawBody, &req, false); err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	egressMode := domain.EgressMode(strings.TrimSpace(req.EgressMode))
	if !egressMode.IsValid() {
		writeError(w, r, s.deps.Logger, domain.BadRequest("INVALID_EGRESS_MODE", "egress_mode must be PASSIVE_AUDIT, ENFORCE_BLOCK, or ENFORCE_PR"))
		return
	}

	var reqDelivery *domain.PassiveAuditDelivery
	if req.PassiveAuditDelivery != nil {
		d := domain.PassiveAuditDelivery(strings.TrimSpace(*req.PassiveAuditDelivery))
		if !d.IsValid() {
			writeError(w, r, s.deps.Logger, domain.BadRequest("INVALID_PASSIVE_AUDIT_DELIVERY", "passive_audit_delivery must be ASYNC or INLINE_WARN"))
			return
		}
		reqDelivery = &d
	}

	var reqRemoteHost *string
	if req.RemoteHost != nil {
		h, err := validateRemoteHost(*req.RemoteHost)
		if err != nil {
			writeError(w, r, s.deps.Logger, err)
			return
		}
		reqRemoteHost = &h
	}

	var reqGitRemoteURL *string
	if req.GitRemoteURL != nil {
		u, err := validateGitRemoteURL(*req.GitRemoteURL)
		if err != nil {
			writeError(w, r, s.deps.Logger, err)
			return
		}
		reqGitRemoteURL = &u
	}

	s.runIdempotent(w, r, caller, idemKey, rawBody, func() (int, any, error) {
		dbCtx, cancel := s.withDBTimeout(r.Context())
		defer cancel()

		now := time.Now().UTC().Truncate(time.Microsecond)
		var resp RepositoryEgressModeResponseDTO

		txErr := s.deps.Store.WithTx(dbCtx, func(tx *persistence.Tx) error {
			existing, err := tx.GetRepositoryByID(dbCtx, repoID)
			if err != nil {
				return err
			}

			delivery := existing.PassiveAuditDelivery
			if delivery == "" {
				delivery = domain.PassiveAuditDeliveryAsync
			}
			if reqDelivery != nil {
				delivery = *reqDelivery
			}

			remoteHost := strings.ToLower(strings.TrimSpace(existing.RemoteHost))
			if remoteHost == "" {
				remoteHost = "github.com"
			}
			if reqRemoteHost != nil {
				remoteHost = *reqRemoteHost
			}

			gitRemoteURL := existing.GitRemoteURL
			if reqGitRemoteURL != nil {
				gitRemoteURL = reqGitRemoteURL
			}

			registeredDest := existing.RegisteredDestination
			if req.RegisteredDestination != nil {
				registeredDest = *req.RegisteredDestination
			}

			external := existing.External
			if req.External != nil {
				external = *req.External
			}

			if _, err := tx.Tx().Exec(dbCtx, `
				UPDATE repositories
				SET egress_mode            = $2,
				    passive_audit_delivery = $3,
				    git_remote_url         = $4,
				    remote_host            = $5,
				    registered_destination = $6,
				    external               = $7
				WHERE id = $1
			`, repoID, string(egressMode), string(delivery), gitRemoteURL, remoteHost, registeredDest, external); err != nil {
				return persistence.MapError(err)
			}

			payloadBytes, _ := json.Marshal(map[string]any{
				"repository_id":          repoID.String(),
				"egress_mode":            string(egressMode),
				"passive_audit_delivery": string(delivery),
				"remote_host":            remoteHost,
				"registered_destination": registeredDest,
				"external":               external,
			})
			if _, err := audit.AppendTx(dbCtx, tx, audit.AppendInput{
				EventType:    "repository.egress_mode_updated",
				ActorID:      &caller.Principal.ID,
				ResourceType: "repository",
				ResourceID:   repoID,
				Payload:      payloadBytes,
				CreatedAt:    now,
			}, s.deps.Logger); err != nil {
				return err
			}

			updatedStr := formatTimestamp(now)
			resp = RepositoryEgressModeResponseDTO{
				RepositoryID:          repoID.String(),
				FullName:              optString(existing.FullName),
				EgressMode:            string(egressMode),
				PassiveAuditDelivery:  string(delivery),
				GitRemoteURL:          gitRemoteURL,
				RemoteHost:            optString(remoteHost),
				RegisteredDestination: registeredDest,
				External:              external,
				UpdatedAt:             &updatedStr,
			}
			return nil
		})
		if txErr != nil {
			return 0, nil, mapDBTimeoutError(dbCtx, txErr)
		}
		return http.StatusOK, resp, nil
	})
}
