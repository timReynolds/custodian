package decisions

import (
	"errors"
	"testing"

	"github.com/timreynolds/custodian/internal/domain"
)

func TestAuthorizeModelRoute(t *testing.T) {
	t.Parallel()

	enabledRepo := domain.Repository{
		ID:             domain.MustNewID(),
		FullName:       "org/repo",
		Classification: domain.ClassificationInternal,
		Enabled:        true,
	}

	t.Run("authorized route passes", func(t *testing.T) {
		t.Parallel()
		err := AuthorizeModelRoute(enabledRepo, []string{"approved-code-review", "other-route"}, "approved-code-review", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("disabled repository rejected", func(t *testing.T) {
		t.Parallel()
		disabled := enabledRepo
		disabled.Enabled = false
		err := AuthorizeModelRoute(disabled, []string{"approved-code-review"}, "approved-code-review", nil)
		if !errors.Is(err, domain.ErrForbidden) {
			t.Fatalf("expected ErrForbidden, got %v", err)
		}
	})

	t.Run("invalid classification rejected", func(t *testing.T) {
		t.Parallel()
		bad := enabledRepo
		bad.Classification = "TOP_SECRET"
		err := AuthorizeModelRoute(bad, []string{"approved-code-review"}, "approved-code-review", nil)
		if !errors.Is(err, domain.ErrForbidden) {
			t.Fatalf("expected ErrForbidden, got %v", err)
		}
	})

	t.Run("empty route rejected", func(t *testing.T) {
		t.Parallel()
		err := AuthorizeModelRoute(enabledRepo, []string{"approved-code-review"}, "   ", nil)
		if !errors.Is(err, domain.ErrForbidden) {
			t.Fatalf("expected ErrForbidden, got %v", err)
		}
	})

	t.Run("route not in allowed list rejected", func(t *testing.T) {
		t.Parallel()
		err := AuthorizeModelRoute(enabledRepo, []string{"restricted-only"}, "approved-code-review", nil)
		if !errors.Is(err, domain.ErrForbidden) {
			t.Fatalf("expected ErrForbidden, got %v", err)
		}
	})

	t.Run("classification route policy enforced", func(t *testing.T) {
		t.Parallel()
		policy := &RoutePolicy{
			ClassificationRoutes: map[domain.Classification][]string{
				domain.ClassificationRestricted: {"restricted-code-review"},
			},
			RequireClassificationRule: true,
			RouteMaxClassification: map[string]domain.Classification{
				"public-only-route": domain.ClassificationPublic,
			},
		}

		restricted := enabledRepo
		restricted.Classification = domain.ClassificationRestricted

		if err := AuthorizeModelRoute(restricted, []string{"restricted-code-review"}, "restricted-code-review", policy); err != nil {
			t.Fatalf("expected restricted route to pass, got %v", err)
		}
		if err := AuthorizeModelRoute(restricted, []string{"approved-code-review"}, "approved-code-review", policy); !errors.Is(err, domain.ErrForbidden) {
			t.Fatalf("expected ErrForbidden for restricted policy mismatch, got %v", err)
		}
		// Classification without rule rejected when RequireClassificationRule=true.
		if err := AuthorizeModelRoute(enabledRepo, []string{"approved-code-review"}, "approved-code-review", policy); !errors.Is(err, domain.ErrForbidden) {
			t.Fatalf("expected ErrForbidden when classification missing from policy, got %v", err)
		}

		// Max classification ceiling enforced.
		policyNoReq := &RoutePolicy{
			RouteMaxClassification: map[string]domain.Classification{
				"public-only-route": domain.ClassificationPublic,
			},
		}
		if err := AuthorizeModelRoute(enabledRepo, []string{"public-only-route"}, "public-only-route", policyNoReq); !errors.Is(err, domain.ErrForbidden) {
			t.Fatalf("expected ErrForbidden when repo classification exceeds route max, got %v", err)
		}
	})
}
