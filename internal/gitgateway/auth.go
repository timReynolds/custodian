package gitgateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/ssh"

	"github.com/timreynolds/custodian/internal/auth"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/identity"
	"github.com/timreynolds/custodian/internal/persistence"
)

const (
	headerDelegatedUpstreamToken = "X-Custodian-Upstream-Token"
	headerGitHubDelegatedToken   = "X-GitHub-Token"
	basicAccessTokenUsername     = "x-access-token"
)

// PrincipalGroupUpserter persists OIDC group memberships after identity resolution.
type PrincipalGroupUpserter interface {
	UpsertPrincipal(ctx context.Context, arg persistence.UpsertPrincipalParams) (persistence.PrincipalRow, error)
}

// SSHPrincipalLookup resolves existing principals for SSH User-CA authentication without auto-provisioning.
type SSHPrincipalLookup interface {
	LookupBySSHPrincipals(ctx context.Context, candidates []string) (persistence.PrincipalRow, error)
}

// AuthenticatorConfig configures HTTPS OIDC and SSH User-CA authentication.
type AuthenticatorConfig struct {
	OIDC          auth.TokenVerifier
	Directory     *identity.Directory
	Store         *persistence.Store
	GroupUpserter PrincipalGroupUpserter
	SSHLookup     SSHPrincipalLookup
	SSHHostKey    ssh.Signer
	SSHUserCA     ssh.PublicKey
	Clock         func() time.Time
	Logger        *slog.Logger
	AuthRealm     string
}

// Authenticator verifies caller identity across HTTPS (OIDC Bearer / Basic) and SSH (User-CA certificates).
type Authenticator struct {
	oidc          auth.TokenVerifier
	directory     *identity.Directory
	groupUpserter PrincipalGroupUpserter
	sshLookup     SSHPrincipalLookup
	sshHostKey    ssh.Signer
	sshUserCA     ssh.PublicKey
	clock         func() time.Time
	logger        *slog.Logger
	authRealm     string
}

// NewAuthenticator builds a gateway Authenticator.
func NewAuthenticator(cfg AuthenticatorConfig) (*Authenticator, error) {
	if cfg.OIDC == nil {
		return nil, domain.BadRequest("INVALID_AUTH_CONFIG", "OIDC verifier is required")
	}
	if cfg.Directory == nil {
		return nil, domain.BadRequest("INVALID_AUTH_CONFIG", "identity directory is required")
	}
	groupUpserter := cfg.GroupUpserter
	if groupUpserter == nil && cfg.Store != nil {
		groupUpserter = cfg.Store
	}
	sshLookup := cfg.SSHLookup
	if sshLookup == nil && cfg.Store != nil && cfg.Store.Pool() != nil {
		sshLookup = &pgSSHPrincipalLookup{store: cfg.Store}
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	realm := strings.TrimSpace(cfg.AuthRealm)
	if realm == "" {
		realm = "Custodian"
	}
	return &Authenticator{
		oidc:          cfg.OIDC,
		directory:     cfg.Directory,
		groupUpserter: groupUpserter,
		sshLookup:     sshLookup,
		sshHostKey:    cfg.SSHHostKey,
		sshUserCA:     cfg.SSHUserCA,
		clock:         clock,
		logger:        cfg.Logger,
		authRealm:     realm,
	}, nil
}

// WWWAuthenticateHeader returns the Basic auth challenge header expected by git credential helpers.
func (a *Authenticator) WWWAuthenticateHeader() string {
	realm := "Custodian"
	if a != nil && a.authRealm != "" {
		realm = a.authRealm
	}
	return fmt.Sprintf(`Basic realm=%q`, realm)
}

// AuthenticateHTTPRequest authenticates an HTTPS request using OIDC Bearer or Basic x-access-token:<jwt>,
// resolves/provisions the principal, persists OIDC groups, and extracts any delegated upstream token.
func (a *Authenticator) AuthenticateHTTPRequest(ctx context.Context, r *http.Request) (AuthenticatedPrincipal, error) {
	if a == nil || a.oidc == nil || a.directory == nil {
		return AuthenticatedPrincipal{}, domain.Unavailable("AUTH_UNAVAILABLE", "authenticator is not configured")
	}
	if r == nil {
		return AuthenticatedPrincipal{}, domain.Unauthorized("MISSING_CREDENTIALS", "authentication required")
	}

	rawJWT, err := extractHTTPJWT(r)
	if err != nil {
		return AuthenticatedPrincipal{}, err
	}

	claims, err := a.oidc.Verify(ctx, rawJWT)
	if err != nil {
		return AuthenticatedPrincipal{}, err
	}

	caller, err := a.directory.ResolveCaller(ctx, claims)
	if err != nil {
		return AuthenticatedPrincipal{}, err
	}

	groups := append([]string(nil), claims.Groups...)
	if len(groups) > 0 && a.groupUpserter != nil {
		if _, err := a.groupUpserter.UpsertPrincipal(ctx, persistence.UpsertPrincipalParams{
			ID:            caller.Principal.ID,
			Kind:          caller.Principal.Kind,
			Issuer:        caller.Principal.Issuer,
			Subject:       caller.Principal.Subject,
			DisplayName:   caller.Principal.DisplayName,
			VerifiedEmail: caller.Principal.VerifiedEmail,
			Groups:        groups,
			CreatedAt:     caller.Principal.CreatedAt,
		}); err != nil {
			return AuthenticatedPrincipal{}, err
		}
	}

	delegated, err := extractDelegatedUpstreamToken(r)
	if err != nil {
		return AuthenticatedPrincipal{}, err
	}

	return AuthenticatedPrincipal{
		Principal:              caller.Principal,
		Groups:                 groups,
		AuthMethod:             "oidc",
		OIDCToken:              rawJWT,
		DelegatedUpstreamToken: delegated,
	}, nil
}

func extractHTTPJWT(r *http.Request) (string, error) {
	if user, pass, ok := r.BasicAuth(); ok {
		if !strings.EqualFold(strings.TrimSpace(user), basicAccessTokenUsername) || strings.TrimSpace(pass) == "" {
			return "", domain.Unauthorized("INVALID_BASIC_CREDENTIALS", "basic authentication requires username x-access-token and non-empty token")
		}
		if hasControlOrWhitespace(pass) {
			return "", domain.Unauthorized("INVALID_BEARER_TOKEN", "token contains invalid characters")
		}
		return strings.TrimSpace(pass), nil
	}

	authHdr := r.Header.Get("Authorization")
	if strings.TrimSpace(authHdr) == "" {
		return "", domain.Unauthorized("UNAUTHORIZED", "authentication required")
	}
	tok, err := auth.ExtractBearerToken(authHdr)
	if err != nil {
		return "", err
	}
	return tok, nil
}

func extractDelegatedUpstreamToken(r *http.Request) (string, error) {
	tok := strings.TrimSpace(r.Header.Get(headerDelegatedUpstreamToken))
	if tok == "" {
		tok = strings.TrimSpace(r.Header.Get(headerGitHubDelegatedToken))
	}
	if tok == "" {
		return "", nil
	}
	if hasControlOrWhitespace(tok) {
		return "", domain.BadRequest("INVALID_UPSTREAM_TOKEN", "delegated upstream token contains invalid characters")
	}
	return tok, nil
}

func hasControlOrWhitespace(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || unicode.IsControl(r) || unicode.IsSpace(r) {
			return true
		}
	}
	return false
}

// SSHSessionRegistry tracks authenticated principals keyed by SSH connection session ID.
type SSHSessionRegistry struct {
	mu       sync.RWMutex
	sessions map[string]AuthenticatedPrincipal
}

// NewSSHSessionRegistry creates a thread-safe SSHSessionRegistry.
func NewSSHSessionRegistry() *SSHSessionRegistry {
	return &SSHSessionRegistry{
		sessions: make(map[string]AuthenticatedPrincipal),
	}
}

func (r *SSHSessionRegistry) put(sessionID []byte, principal AuthenticatedPrincipal) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[string(sessionID)] = principal
}

// Get retrieves the AuthenticatedPrincipal associated with an SSH connection session ID.
func (r *SSHSessionRegistry) Get(sessionID []byte) (AuthenticatedPrincipal, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.sessions[string(sessionID)]
	return p, ok
}

// Delete removes the AuthenticatedPrincipal for a closed SSH session.
func (r *SSHSessionRegistry) Delete(sessionID []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, string(sessionID))
}

// BuildSSHServerConfig constructs an *ssh.ServerConfig enforcing OpenSSH User-CA certificates
// without auto-provisioning unknown principals, and returns the session registry for lookups.
func (a *Authenticator) BuildSSHServerConfig() (*ssh.ServerConfig, *SSHSessionRegistry, error) {
	if a == nil {
		return nil, nil, domain.Unavailable("AUTH_UNAVAILABLE", "authenticator is not configured")
	}
	if a.sshHostKey == nil {
		return nil, nil, domain.BadRequest("INVALID_SSH_CONFIG", "SSH host key signer is required")
	}
	if a.sshUserCA == nil {
		return nil, nil, domain.BadRequest("INVALID_SSH_CONFIG", "SSH user CA public key is required")
	}
	if a.sshLookup == nil {
		return nil, nil, domain.Unavailable("AUTH_UNAVAILABLE", "SSH principal lookup store is required")
	}

	caWire := a.sshUserCA.Marshal()
	checker := &ssh.CertChecker{
		IsUserAuthority: func(authKey ssh.PublicKey) bool {
			return authKey != nil && bytes.Equal(authKey.Marshal(), caWire)
		},
		Clock: a.clock,
	}

	registry := NewSSHSessionRegistry()
	srvCfg := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			cert, ok := key.(*ssh.Certificate)
			if !ok {
				return nil, errors.New("ssh user certificate required")
			}
			if cert.CertType != ssh.UserCert {
				return nil, errors.New("ssh certificate is not a user certificate")
			}
			if len(cert.ValidPrincipals) == 0 {
				return nil, errors.New("ssh user certificate has empty valid principals")
			}
			if !checker.IsUserAuthority(cert.SignatureKey) {
				return nil, errors.New("untrusted ssh user certificate authority")
			}

			username := strings.TrimSpace(conn.User())
			if username == "" {
				return nil, errors.New("ssh username is required")
			}

			checkPrincipal := username
			var candidates []string
			if username == "git" {
				checkPrincipal = cert.ValidPrincipals[0]
				candidates = append(candidates, cert.ValidPrincipals...)
			} else {
				if !slices.Contains(cert.ValidPrincipals, username) {
					return nil, errors.New("ssh username is not listed in certificate principals")
				}
				candidates = []string{username}
			}

			if err := checker.CheckCert(checkPrincipal, cert); err != nil {
				return nil, fmt.Errorf("ssh certificate validation failed: %w", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			row, err := a.sshLookup.LookupBySSHPrincipals(ctx, candidates)
			if err != nil {
				return nil, fmt.Errorf("ssh principal not registered: %w", err)
			}

			dom := row.ToDomain()
			groups := append([]string(nil), row.Groups...)
			registry.put(conn.SessionID(), AuthenticatedPrincipal{
				Principal:     dom,
				Groups:        groups,
				AuthMethod:    "ssh_cert",
				SSHKeyID:      cert.KeyId,
				SSHCertSerial: cert.Serial,
			})

			return &ssh.Permissions{
				Extensions: map[string]string{
					"principal_id":    dom.ID.String(),
					"ssh_key_id":      cert.KeyId,
					"ssh_cert_serial": fmt.Sprintf("%d", cert.Serial),
				},
			}, nil
		},
	}
	srvCfg.AddHostKey(a.sshHostKey)
	return srvCfg, registry, nil
}

type pgSSHPrincipalLookup struct {
	store *persistence.Store
}

const lookupSSHPrincipalSQL = `
SELECT id, kind, issuer, subject, display_name, verified_email, groups, created_at
FROM principals
WHERE subject = ANY($1::text[]) OR verified_email = ANY($1::text[])
ORDER BY LEAST(
           COALESCE(array_position($1::text[], subject), 2147483647),
           COALESCE(array_position($1::text[], verified_email), 2147483647)
         ) ASC,
         CASE WHEN subject = ANY($1::text[]) THEN 0 ELSE 1 END,
         CASE WHEN kind = 'HUMAN' THEN 0 ELSE 1 END,
         created_at ASC, id ASC
LIMIT 1
`

func (l *pgSSHPrincipalLookup) LookupBySSHPrincipals(ctx context.Context, candidates []string) (persistence.PrincipalRow, error) {
	if l == nil || l.store == nil || l.store.Pool() == nil {
		return persistence.PrincipalRow{}, domain.Unavailable("STORE_UNAVAILABLE", "persistence store is unavailable")
	}
	clean := make([]string, 0, len(candidates))
	seen := make(map[string]struct{}, len(candidates))
	for _, c := range candidates {
		if trimmed := strings.TrimSpace(c); trimmed != "" {
			if _, ok := seen[trimmed]; !ok {
				seen[trimmed] = struct{}{}
				clean = append(clean, trimmed)
			}
		}
	}
	if len(clean) == 0 {
		return persistence.PrincipalRow{}, domain.Unauthorized("UNKNOWN_SSH_PRINCIPAL", "no SSH principal candidates provided")
	}

	var row persistence.PrincipalRow
	var kind string
	err := l.store.Pool().QueryRow(ctx, lookupSSHPrincipalSQL, clean).Scan(
		&row.ID,
		&kind,
		&row.Issuer,
		&row.Subject,
		&row.DisplayName,
		&row.VerifiedEmail,
		&row.Groups,
		&row.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return persistence.PrincipalRow{}, domain.Unauthorized("UNKNOWN_SSH_PRINCIPAL", "ssh certificate principal is not registered")
		}
		return persistence.PrincipalRow{}, persistence.MapError(err)
	}
	row.Kind = domain.PrincipalKind(kind)
	if row.Groups == nil {
		row.Groups = []string{}
	}
	return row, nil
}
