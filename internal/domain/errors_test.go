package domain

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestHTTPStatusFromError(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		status int
	}{
		{"nil", nil, http.StatusOK},
		{"bad_request", ErrBadRequest, 400},
		{"unauthorized", ErrUnauthorized, 401},
		{"forbidden", ErrForbidden, 403},
		{"not_found", ErrNotFound, 404},
		{"conflict", ErrConflict, 409},
		{"unprocessable", ErrUnprocessable, 422},
		{"rate_limited", ErrRateLimited, 429},
		{"unavailable", ErrUnavailable, 503},
		{"internal", ErrInternal, 500},
		{"unknown", errors.New("boom"), 500},
		{"wrapped_conflict", Conflict("VERSION_MISMATCH", "stale version"), 409},
		{"wrapped_unprocessable", Unprocessable("UNSAFE_ARCHIVE", "symlink rejected"), 422},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := HTTPStatusFromError(tc.err); got != tc.status {
				t.Fatalf("HTTPStatusFromError() = %d, want %d", got, tc.status)
			}
		})
	}
}

func TestDomainErrorBehavior(t *testing.T) {
	cause := errors.New("pg connection refused")
	err := WrapError(ErrUnavailable, "STORE_DOWN", "artifact store temporarily unavailable", cause)

	if err.HTTPStatus() != 503 {
		t.Fatalf("HTTPStatus() = %d, want 503", err.HTTPStatus())
	}
	if err.Code() != "STORE_DOWN" {
		t.Fatalf("Code() = %q, want STORE_DOWN", err.Code())
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Fatal("errors.Is(err, ErrUnavailable) = false")
	}
	if !errors.Is(err, cause) {
		t.Fatal("errors.Is(err, cause) = false")
	}
	var dom *DomainError
	if !errors.As(err, &dom) {
		t.Fatal("errors.As failed")
	}
	if !strings.Contains(err.Error(), "STORE_DOWN") {
		t.Fatalf("Error() missing code: %q", err.Error())
	}

	raw, marshalErr := json.Marshal(err)
	if marshalErr != nil {
		t.Fatalf("json.Marshal failed: %v", marshalErr)
	}
	if strings.Contains(string(raw), "pg connection refused") {
		t.Fatalf("internal Cause leaked into JSON: %s", raw)
	}
}
