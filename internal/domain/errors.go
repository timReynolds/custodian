package domain

import (
	"errors"
	"fmt"
	"net/http"
)

var (
	// ErrBadRequest maps to HTTP 400.
	ErrBadRequest = errors.New("bad request")
	// ErrUnauthorized maps to HTTP 401.
	ErrUnauthorized = errors.New("unauthorized")
	// ErrForbidden maps to HTTP 403.
	ErrForbidden = errors.New("forbidden")
	// ErrNotFound maps to HTTP 404.
	ErrNotFound = errors.New("not found")
	// ErrConflict maps to HTTP 409.
	ErrConflict = errors.New("conflict")
	// ErrUnprocessable maps to HTTP 422.
	ErrUnprocessable = errors.New("unprocessable entity")
	// ErrRateLimited maps to HTTP 429.
	ErrRateLimited = errors.New("rate limited")
	// ErrUnavailable maps to HTTP 503.
	ErrUnavailable = errors.New("service unavailable")
	// ErrInternal maps to HTTP 500.
	ErrInternal = errors.New("internal error")
)

// DomainError carries a public safe code/message and HTTP status while hiding internal Cause from JSON.
type DomainError struct {
	Sentinel error  `json:"-"`
	Status   int    `json:"status"`
	ErrCode  string `json:"code"`
	Message  string `json:"message"`
	Cause    error  `json:"-"`
}

func (e *DomainError) Error() string {
	if e == nil {
		return ""
	}
	if e.ErrCode == "" {
		return e.Message
	}
	if e.Message == "" {
		return e.ErrCode
	}
	return fmt.Sprintf("%s: %s", e.ErrCode, e.Message)
}

// HTTPStatus returns the HTTP status code associated with this DomainError.
func (e *DomainError) HTTPStatus() int {
	if e == nil {
		return http.StatusInternalServerError
	}
	if e.Status != 0 {
		return e.Status
	}
	return statusForSentinel(e.Sentinel)
}

// Code returns the machine-readable error code.
func (e *DomainError) Code() string {
	if e == nil {
		return ""
	}
	if e.ErrCode != "" {
		return e.ErrCode
	}
	return defaultCodeForStatus(e.HTTPStatus())
}

// Unwrap returns the underlying Cause for errors.Is / errors.As traversal.
func (e *DomainError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// Is enables errors.Is(err, domain.ErrForbidden) matching via Sentinel.
func (e *DomainError) Is(target error) bool {
	if e == nil || e.Sentinel == nil {
		return false
	}
	return errors.Is(e.Sentinel, target)
}

// NewError creates a DomainError mapped to the given sentinel error.
func NewError(sentinel error, code, message string) *DomainError {
	return WrapError(sentinel, code, message, nil)
}

// WrapError creates a DomainError mapped to sentinel while retaining an internal cause.
func WrapError(sentinel error, code, message string, cause error) *DomainError {
	if sentinel == nil {
		sentinel = ErrInternal
	}
	status := statusForSentinel(sentinel)
	if code == "" {
		code = defaultCodeForStatus(status)
	}
	return &DomainError{
		Sentinel: sentinel,
		Status:   status,
		ErrCode:  code,
		Message:  message,
		Cause:    cause,
	}
}

func BadRequest(code, msg string) *DomainError {
	return NewError(ErrBadRequest, code, msg)
}

func Unauthorized(code, msg string) *DomainError {
	return NewError(ErrUnauthorized, code, msg)
}

func Forbidden(code, msg string) *DomainError {
	return NewError(ErrForbidden, code, msg)
}

func NotFound(code, msg string) *DomainError {
	return NewError(ErrNotFound, code, msg)
}

func Conflict(code, msg string) *DomainError {
	return NewError(ErrConflict, code, msg)
}

func Unprocessable(code, msg string) *DomainError {
	return NewError(ErrUnprocessable, code, msg)
}

func RateLimited(code, msg string) *DomainError {
	return NewError(ErrRateLimited, code, msg)
}

func Unavailable(code, msg string) *DomainError {
	return NewError(ErrUnavailable, code, msg)
}

func Internal(code, msg string) *DomainError {
	return NewError(ErrInternal, code, msg)
}

// HTTPStatusFromError resolves an error to its canonical HTTP status code, defaulting to 500.
func HTTPStatusFromError(err error) int {
	if err == nil {
		return http.StatusOK
	}
	var domErr *DomainError
	if errors.As(err, &domErr) {
		return domErr.HTTPStatus()
	}
	switch {
	case errors.Is(err, ErrBadRequest):
		return http.StatusBadRequest
	case errors.Is(err, ErrUnauthorized):
		return http.StatusUnauthorized
	case errors.Is(err, ErrForbidden):
		return http.StatusForbidden
	case errors.Is(err, ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrConflict):
		return http.StatusConflict
	case errors.Is(err, ErrUnprocessable):
		return http.StatusUnprocessableEntity
	case errors.Is(err, ErrRateLimited):
		return http.StatusTooManyRequests
	case errors.Is(err, ErrUnavailable):
		return http.StatusServiceUnavailable
	case errors.Is(err, ErrInternal):
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
}

func statusForSentinel(sentinel error) int {
	switch {
	case errors.Is(sentinel, ErrBadRequest):
		return http.StatusBadRequest
	case errors.Is(sentinel, ErrUnauthorized):
		return http.StatusUnauthorized
	case errors.Is(sentinel, ErrForbidden):
		return http.StatusForbidden
	case errors.Is(sentinel, ErrNotFound):
		return http.StatusNotFound
	case errors.Is(sentinel, ErrConflict):
		return http.StatusConflict
	case errors.Is(sentinel, ErrUnprocessable):
		return http.StatusUnprocessableEntity
	case errors.Is(sentinel, ErrRateLimited):
		return http.StatusTooManyRequests
	case errors.Is(sentinel, ErrUnavailable):
		return http.StatusServiceUnavailable
	case errors.Is(sentinel, ErrInternal):
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
}

func defaultCodeForStatus(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "BAD_REQUEST"
	case http.StatusUnauthorized:
		return "UNAUTHORIZED"
	case http.StatusForbidden:
		return "FORBIDDEN"
	case http.StatusNotFound:
		return "NOT_FOUND"
	case http.StatusConflict:
		return "CONFLICT"
	case http.StatusUnprocessableEntity:
		return "UNPROCESSABLE_ENTITY"
	case http.StatusTooManyRequests:
		return "RATE_LIMITED"
	case http.StatusServiceUnavailable:
		return "UNAVAILABLE"
	default:
		return "INTERNAL_ERROR"
	}
}
