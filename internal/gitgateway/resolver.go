package gitgateway

import (
	"context"
	"errors"
	"strings"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/persistence"
)

// RepositoryLookup abstracts the persistence lookups required by TargetResolver.
type RepositoryLookup interface {
	GetRepositoryByGitRemoteURL(ctx context.Context, remoteURL string) (persistence.RepositoryRow, error)
	GetRepositoryByFullName(ctx context.Context, fullName string) (persistence.RepositoryRow, error)
}

// TargetResolverConfig configures repository and egress mode resolution.
type TargetResolverConfig struct {
	Store                RepositoryLookup
	UpstreamBaseURL      string
	DefaultEgressMode    domain.EgressMode           // defaults to ENFORCE_BLOCK
	DefaultAuditDelivery domain.PassiveAuditDelivery // defaults to ASYNC
}

// TargetResolver resolves owner/repo targets against persisted repositories and org-wide defaults.
type TargetResolver struct {
	store                RepositoryLookup
	upstreamBaseURL      string
	upstreamHost         string
	defaultEgressMode    domain.EgressMode
	defaultAuditDelivery domain.PassiveAuditDelivery
}

// NewTargetResolver constructs a TargetResolver with safe fail-closed defaults.
func NewTargetResolver(cfg TargetResolverConfig) (*TargetResolver, error) {
	egressMode := cfg.DefaultEgressMode
	if egressMode == "" {
		egressMode = domain.EgressModeEnforceBlock
	}
	if !egressMode.IsValid() {
		return nil, domain.BadRequest("INVALID_EGRESS_MODE", "invalid default egress mode")
	}
	delivery := cfg.DefaultAuditDelivery
	if delivery == "" {
		delivery = domain.PassiveAuditDeliveryAsync
	}
	if !delivery.IsValid() {
		return nil, domain.BadRequest("INVALID_PASSIVE_AUDIT_DELIVERY", "invalid default passive audit delivery")
	}

	upstreamBase := strings.TrimRight(strings.TrimSpace(cfg.UpstreamBaseURL), "/")
	upstreamHost := NormalizeHostFromURL(upstreamBase)

	return &TargetResolver{
		store:                cfg.Store,
		upstreamBaseURL:      upstreamBase,
		upstreamHost:         upstreamHost,
		defaultEgressMode:    egressMode,
		defaultAuditDelivery: delivery,
	}, nil
}

// Resolve looks up ownerRepo in the repository catalog, rejects disabled repositories,
// canonicalizes the destination host/path, and resolves effective egress settings.
func (r *TargetResolver) Resolve(ctx context.Context, ownerRepo, requestHost string) (ResolvedTarget, error) {
	if err := validateOwnerRepo(ownerRepo); err != nil {
		return ResolvedTarget{}, err
	}

	fallbackHost := r.upstreamHost
	if fallbackHost == "" {
		fallbackHost = strings.ToLower(strings.TrimSpace(requestHost))
	}
	if fallbackHost == "" {
		fallbackHost = "github.com"
	}

	var row persistence.RepositoryRow
	var found bool

	if r.store != nil {
		candidates := r.candidateRemoteURLs(ownerRepo, fallbackHost)
		for _, candidate := range candidates {
			got, err := r.store.GetRepositoryByGitRemoteURL(ctx, candidate)
			if err == nil {
				row = got
				found = true
				break
			}
			if !errors.Is(err, domain.ErrNotFound) {
				return ResolvedTarget{}, err
			}
		}

		if !found {
			got, err := r.store.GetRepositoryByFullName(ctx, ownerRepo)
			if err == nil {
				row = got
				found = true
			} else if !errors.Is(err, domain.ErrNotFound) {
				return ResolvedTarget{}, err
			}
		}
	}

	if found {
		dom := row.ToDomain()
		if !dom.Enabled {
			return ResolvedTarget{}, domain.Forbidden("REPOSITORY_DISABLED", "repository is disabled")
		}
		destHost := strings.ToLower(strings.TrimSpace(dom.RemoteHost))
		if destHost == "" {
			destHost = fallbackHost
		}
		canonDest, host, err := CanonicalizeDestination(destHost+"/"+ownerRepo, fallbackHost)
		if err != nil {
			return ResolvedTarget{}, err
		}
		egressMode := dom.EgressMode
		if !egressMode.IsValid() {
			egressMode = r.defaultEgressMode
		}
		delivery := dom.PassiveAuditDelivery
		if !delivery.IsValid() {
			delivery = r.defaultAuditDelivery
		}
		return ResolvedTarget{
			OwnerRepo:            ownerRepo,
			CanonicalDestination: canonDest,
			Host:                 host,
			Repository:           &dom,
			AllowedModelRoutes:   append([]string(nil), row.AllowedModelRoutes...),
			Registered:           dom.RegisteredDestination,
			External:             dom.External,
			EgressMode:           egressMode,
			PassiveAuditDelivery: delivery,
		}, nil
	}

	canonDest, host, err := CanonicalizeDestination(ownerRepo, fallbackHost)
	if err != nil {
		return ResolvedTarget{}, err
	}
	return ResolvedTarget{
		OwnerRepo:            ownerRepo,
		CanonicalDestination: canonDest,
		Host:                 host,
		Repository:           nil,
		Registered:           false,
		External:             true,
		EgressMode:           r.defaultEgressMode,
		PassiveAuditDelivery: r.defaultAuditDelivery,
	}, nil
}

func (r *TargetResolver) candidateRemoteURLs(ownerRepo, fallbackHost string) []string {
	seen := make(map[string]struct{}, 6)
	var out []string
	add := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" {
			return
		}
		if _, ok := seen[u]; ok {
			return
		}
		seen[u] = struct{}{}
		out = append(out, u)
	}
	if r.upstreamBaseURL != "" {
		add(r.upstreamBaseURL + "/" + ownerRepo + ".git")
		add(r.upstreamBaseURL + "/" + ownerRepo)
	}
	if fallbackHost != "" {
		add("https://" + fallbackHost + "/" + ownerRepo + ".git")
		add("https://" + fallbackHost + "/" + ownerRepo)
		add(fallbackHost + "/" + ownerRepo + ".git")
		add(fallbackHost + "/" + ownerRepo)
	}
	return out
}
