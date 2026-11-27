package identity

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/auth"
	"github.com/timreynolds/custodian/internal/domain"
)

const agentTypeIssuer = "custodian://agent-type"

// CallerContext binds a resolved persisted Principal to its verified OIDC/workload claims.
type CallerContext struct {
	Principal domain.Principal
	Claims    auth.VerifiedClaims
}

func (c CallerContext) IsHuman() bool {
	return c.Principal.Kind == domain.PrincipalKindHuman
}

func (c CallerContext) IsService() bool {
	return c.Principal.Kind == domain.PrincipalKindService
}

func (c CallerContext) IsAgent() bool {
	return c.Principal.Kind == domain.PrincipalKindAgent
}

func (c CallerContext) IsController() bool {
	return c.IsService() && (c.Claims.TokenKind == auth.TokenKindController || c.HasRole("controller"))
}

func (c CallerContext) IsAuditor() bool {
	return c.IsHuman() && (c.Claims.TokenKind == auth.TokenKindAuditor || c.HasRole("auditor"))
}

func (c CallerContext) IsPolicyAdmin() bool {
	return c.IsHuman() && (c.Claims.TokenKind == auth.TokenKindPolicyAdmin || c.HasRole("policy_admin"))
}

func (c CallerContext) HasRole(role string) bool {
	target := strings.TrimSpace(role)
	if target == "" {
		return false
	}
	for _, r := range c.Claims.Roles {
		if strings.EqualFold(r, target) {
			return true
		}
	}
	return false
}

func (c CallerContext) InGroup(group string) bool {
	target := strings.TrimSpace(group)
	if target == "" {
		return false
	}
	for _, g := range c.Claims.Groups {
		if strings.EqualFold(g, target) {
			return true
		}
	}
	return false
}

// DirectoryConfig configures how verified OIDC/workload claims map to persisted Principals.
type DirectoryConfig struct {
	AutoProvisionHumans    bool
	AutoProvisionWorkloads bool
	RequireVerifiedEmail   bool
	Now                    func() time.Time
	Logger                 *slog.Logger
}

// DefaultDirectoryConfig returns secure default settings for Directory.
func DefaultDirectoryConfig() DirectoryConfig {
	return DirectoryConfig{
		AutoProvisionHumans:    true,
		AutoProvisionWorkloads: true,
		RequireVerifiedEmail:   true,
	}
}

// Directory resolves verified caller claims against a domain.PrincipalStore.
type Directory struct {
	store  domain.PrincipalStore
	cfg    DirectoryConfig
	now    func() time.Time
	logger *slog.Logger
}

// NewDirectory constructs a Directory backed by store.
func NewDirectory(store domain.PrincipalStore, cfg DirectoryConfig) (*Directory, error) {
	if store == nil {
		return nil, domain.BadRequest("INVALID_DIRECTORY_CONFIG", "principal store is required")
	}
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	return &Directory{
		store:  store,
		cfg:    cfg,
		now:    nowFn,
		logger: cfg.Logger,
	}, nil
}

// ResolveCaller resolves a verified token's (issuer, subject) to a Principal.
// Kind escalation on an existing (issuer, subject) is strictly rejected.
func (d *Directory) ResolveCaller(ctx context.Context, claims auth.VerifiedClaims) (CallerContext, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	issuer := strings.TrimSpace(claims.Issuer)
	subject := strings.TrimSpace(claims.Subject)
	if issuer == "" || subject == "" || !claims.Kind.IsValid() {
		return CallerContext{}, domain.Unauthorized("INVALID_CALLER_CLAIMS", "verified claims lack issuer, subject, or valid kind")
	}

	existing, err := d.store.GetByIssuerSubject(ctx, issuer, subject)
	if err == nil {
		if existing.Kind != claims.Kind {
			d.logEvent("caller_rejected", existing.ID, "kind_mismatch")
			return CallerContext{}, domain.Forbidden("PRINCIPAL_KIND_MISMATCH", "principal kind does not match directory record")
		}
		if hasUnsafeControlChars(existing.DisplayName) || hasUnsafeControlChars(existing.VerifiedEmail) {
			d.logEvent("caller_rejected", existing.ID, "invalid_identity_metadata")
			return CallerContext{}, domain.Unprocessable("INVALID_IDENTITY_METADATA", "principal identity metadata contains invalid control characters")
		}
		d.logEvent("caller_resolved", existing.ID, "ok")
		return CallerContext{Principal: existing, Claims: claims}, nil
	}
	if !errors.Is(err, domain.ErrNotFound) {
		return CallerContext{}, err
	}

	if claims.Kind == domain.PrincipalKindHuman {
		if !d.cfg.AutoProvisionHumans {
			return CallerContext{}, domain.Forbidden("UNKNOWN_PRINCIPAL", "human principal is not registered in directory")
		}
		if d.cfg.RequireVerifiedEmail && (!claims.EmailVerified || strings.TrimSpace(claims.Email) == "") {
			return CallerContext{}, domain.Forbidden("UNVERIFIED_HUMAN_IDENTITY", "human identity requires a verified email address")
		}
	} else {
		if !d.cfg.AutoProvisionWorkloads {
			return CallerContext{}, domain.Forbidden("UNKNOWN_PRINCIPAL", "workload principal is not registered in directory")
		}
	}

	verifiedEmail := ""
	if claims.Kind == domain.PrincipalKindHuman && claims.EmailVerified {
		verifiedEmail = strings.TrimSpace(claims.Email)
	}
	displayName := strings.TrimSpace(claims.DisplayName)
	if displayName == "" && claims.Kind != domain.PrincipalKindHuman {
		displayName = subject
	}
	if hasUnsafeControlChars(displayName) || hasUnsafeControlChars(claims.DisplayName) || hasUnsafeControlChars(verifiedEmail) || hasUnsafeControlChars(claims.Email) {
		return CallerContext{}, domain.Unprocessable("INVALID_IDENTITY_METADATA", "principal identity metadata contains invalid control characters")
	}

	id, err := domain.NewID()
	if err != nil {
		return CallerContext{}, domain.WrapError(domain.ErrInternal, "ID_GENERATION_FAILED", "failed to allocate principal ID", err)
	}

	principal := domain.Principal{
		ID:            id,
		Kind:          claims.Kind,
		Issuer:        issuer,
		Subject:       subject,
		DisplayName:   displayName,
		VerifiedEmail: verifiedEmail,
		CreatedAt:     d.now().UTC(),
	}

	saved, err := d.store.Upsert(ctx, principal)
	if err != nil {
		return CallerContext{}, err
	}
	if saved.Kind != claims.Kind {
		return CallerContext{}, domain.Forbidden("PRINCIPAL_KIND_MISMATCH", "principal kind does not match directory record")
	}
	if hasUnsafeControlChars(saved.DisplayName) || hasUnsafeControlChars(saved.VerifiedEmail) {
		return CallerContext{}, domain.Unprocessable("INVALID_IDENTITY_METADATA", "principal identity metadata contains invalid control characters")
	}
	d.logEvent("caller_provisioned", saved.ID, "created")
	return CallerContext{Principal: saved, Claims: claims}, nil
}

// ResolveOwner resolves the accountable human owner exclusively from server-verified OIDC claims.
// Agents, services, controllers, and humans without a verified email are always rejected.
func (d *Directory) ResolveOwner(ctx context.Context, claims auth.VerifiedClaims) (domain.Principal, error) {
	caller, err := d.ResolveCaller(ctx, claims)
	if err != nil {
		return domain.Principal{}, err
	}
	if !caller.IsHuman() {
		d.logEvent("owner_rejected", caller.Principal.ID, "non_human_caller")
		return domain.Principal{}, domain.Forbidden("HUMAN_OWNER_REQUIRED", "accountable workspace owner must be a verified human principal")
	}
	if !claims.EmailVerified || strings.TrimSpace(claims.Email) == "" {
		d.logEvent("owner_rejected", caller.Principal.ID, "unverified_email_claim")
		return domain.Principal{}, domain.Forbidden("UNVERIFIED_HUMAN_IDENTITY", "accountable workspace owner requires verified email")
	}
	if hasUnsafeControlChars(caller.Principal.DisplayName) || hasUnsafeControlChars(caller.Principal.VerifiedEmail) {
		d.logEvent("owner_rejected", caller.Principal.ID, "invalid_identity_metadata")
		return domain.Principal{}, domain.Unprocessable("INVALID_IDENTITY_METADATA", "owner identity metadata contains invalid control characters")
	}
	if _, _, err := caller.Principal.GitAuthor(); err != nil {
		d.logEvent("owner_rejected", caller.Principal.ID, "invalid_git_author")
		return domain.Principal{}, err
	}
	return caller.Principal, nil
}

// ResolveAgentPrincipal resolves or provisions a separate AGENT Principal for workspace provenance.
func (d *Directory) ResolveAgentPrincipal(ctx context.Context, agentType string) (domain.Principal, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if hasUnsafeControlChars(agentType) {
		return domain.Principal{}, domain.BadRequest("INVALID_AGENT_TYPE", "agent type is invalid or empty")
	}
	normalized := strings.ToLower(strings.TrimSpace(agentType))
	if normalized == "" || strings.ContainsAny(normalized, " \t\r\n/\\") {
		return domain.Principal{}, domain.BadRequest("INVALID_AGENT_TYPE", "agent type is invalid or empty")
	}

	existing, err := d.store.GetByIssuerSubject(ctx, agentTypeIssuer, normalized)
	if err == nil {
		if existing.Kind != domain.PrincipalKindAgent {
			return domain.Principal{}, domain.Forbidden("PRINCIPAL_KIND_MISMATCH", "stored principal is not an agent")
		}
		if hasUnsafeControlChars(existing.DisplayName) {
			return domain.Principal{}, domain.Unprocessable("INVALID_IDENTITY_METADATA", "agent identity metadata contains invalid control characters")
		}
		return existing, nil
	}
	if !errors.Is(err, domain.ErrNotFound) {
		return domain.Principal{}, err
	}

	id, err := domain.NewID()
	if err != nil {
		return domain.Principal{}, domain.WrapError(domain.ErrInternal, "ID_GENERATION_FAILED", "failed to allocate agent principal ID", err)
	}
	saved, err := d.store.Upsert(ctx, domain.Principal{
		ID:          id,
		Kind:        domain.PrincipalKindAgent,
		Issuer:      agentTypeIssuer,
		Subject:     normalized,
		DisplayName: normalized,
		CreatedAt:   d.now().UTC(),
	})
	if err != nil {
		return domain.Principal{}, err
	}
	d.logEvent("agent_resolved", saved.ID, "ok")
	return saved, nil
}

func hasUnsafeControlChars(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return true
		}
	}
	return false
}

// GetByID fetches a Principal by UUID.
func (d *Directory) GetByID(ctx context.Context, id uuid.UUID) (domain.Principal, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if id == uuid.Nil {
		return domain.Principal{}, domain.BadRequest("INVALID_PRINCIPAL_ID", "principal_id must not be nil")
	}
	return d.store.GetByID(ctx, id)
}

func (d *Directory) logEvent(msg string, principalID uuid.UUID, status string) {
	if d.logger == nil {
		return
	}
	d.logger.Info(msg, "principal_id", principalID.String(), "status", status)
}

type issuerSubjectKey struct {
	issuer  string
	subject string
}

// MemoryPrincipalStore is a thread-safe in-memory domain.PrincipalStore for tests and local harnesses.
type MemoryPrincipalStore struct {
	mu        sync.RWMutex
	byID      map[uuid.UUID]domain.Principal
	byIssSubj map[issuerSubjectKey]uuid.UUID
}

var _ domain.PrincipalStore = (*MemoryPrincipalStore)(nil)

// NewMemoryPrincipalStore constructs an empty MemoryPrincipalStore.
func NewMemoryPrincipalStore() *MemoryPrincipalStore {
	return &MemoryPrincipalStore{
		byID:      make(map[uuid.UUID]domain.Principal),
		byIssSubj: make(map[issuerSubjectKey]uuid.UUID),
	}
}

func (s *MemoryPrincipalStore) GetByID(ctx context.Context, id uuid.UUID) (domain.Principal, error) {
	if err := ctx.Err(); err != nil {
		return domain.Principal{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.byID[id]
	if !ok {
		return domain.Principal{}, domain.NotFound("PRINCIPAL_NOT_FOUND", "principal not found")
	}
	return p, nil
}

func (s *MemoryPrincipalStore) GetByIssuerSubject(ctx context.Context, issuer, subject string) (domain.Principal, error) {
	if err := ctx.Err(); err != nil {
		return domain.Principal{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byIssSubj[issuerSubjectKey{issuer: issuer, subject: subject}]
	if !ok {
		return domain.Principal{}, domain.NotFound("PRINCIPAL_NOT_FOUND", "principal not found")
	}
	return s.byID[id], nil
}

func (s *MemoryPrincipalStore) Upsert(ctx context.Context, p domain.Principal) (domain.Principal, error) {
	if err := ctx.Err(); err != nil {
		return domain.Principal{}, err
	}
	if p.ID == uuid.Nil || !p.Kind.IsValid() || strings.TrimSpace(p.Issuer) == "" || strings.TrimSpace(p.Subject) == "" {
		return domain.Principal{}, domain.BadRequest("INVALID_PRINCIPAL", "principal requires valid id, kind, issuer, and subject")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	key := issuerSubjectKey{issuer: p.Issuer, subject: p.Subject}
	if existingID, exists := s.byIssSubj[key]; exists {
		existing := s.byID[existingID]
		if existing.Kind != p.Kind {
			return domain.Principal{}, domain.Forbidden("PRINCIPAL_KIND_MISMATCH", "cannot alter existing principal kind")
		}
		if existing.VerifiedEmail != "" && p.VerifiedEmail == "" {
			p.VerifiedEmail = existing.VerifiedEmail
		}
		if p.DisplayName == "" {
			p.DisplayName = existing.DisplayName
		}
		p.ID = existing.ID
		if p.CreatedAt.IsZero() {
			p.CreatedAt = existing.CreatedAt
		}
		s.byID[existing.ID] = p
		return p, nil
	}

	if existing, exists := s.byID[p.ID]; exists {
		if existing.Issuer != p.Issuer || existing.Subject != p.Subject {
			return domain.Principal{}, domain.Conflict("PRINCIPAL_ID_CONFLICT", "principal ID already exists for another issuer/subject")
		}
	}

	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	s.byID[p.ID] = p
	s.byIssSubj[key] = p.ID
	return p, nil
}

// List returns a snapshot of all stored principals ordered by ID string (helpful for diagnostics).
func (s *MemoryPrincipalStore) List() []domain.Principal {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]domain.Principal, 0, len(s.byID))
	for _, p := range s.byID {
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b domain.Principal) int {
		return strings.Compare(a.ID.String(), b.ID.String())
	})
	return out
}
