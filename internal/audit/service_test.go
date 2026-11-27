package audit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/audit"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/harness"
	"github.com/timreynolds/custodian/internal/observability"
	"github.com/timreynolds/custodian/internal/persistence"
)

type memAuditStore struct {
	mu     sync.Mutex
	head   persistence.AuditChainHeadRow
	events []persistence.AuditEventRow
}

func newMemAuditStore() *memAuditStore {
	return &memAuditStore{
		head: persistence.AuditChainHeadRow{ChainID: "default"},
	}
}

func (m *memAuditStore) LockAuditChainHead(_ context.Context) (persistence.AuditChainHeadRow, error) {
	return m.head, nil
}

func (m *memAuditStore) NormalizeJSONB(_ context.Context, payload json.RawMessage) (json.RawMessage, error) {
	canonical, err := domain.CanonicalJSONBytes(payload)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(canonical), nil
}

func (m *memAuditStore) UpdateAuditChainHead(_ context.Context, eventID uuid.UUID, eventHash string, eventCount int64, updatedAt time.Time) error {
	m.head.LastEventID = &eventID
	m.head.LastEventHash = &eventHash
	m.head.EventCount = eventCount
	m.head.UpdatedAt = updatedAt
	return nil
}

func (m *memAuditStore) InsertAuditEvent(_ context.Context, arg persistence.InsertAuditEventParams) (persistence.AuditEventRow, error) {
	var prev *string
	if arg.PreviousHash != "" {
		p := arg.PreviousHash
		prev = &p
	}
	row := persistence.AuditEventRow{
		ID:           arg.ID,
		ChainSeq:     arg.ChainSeq,
		EventType:    arg.EventType,
		ActorID:      arg.ActorID,
		ResourceType: arg.ResourceType,
		ResourceID:   arg.ResourceID,
		Payload:      arg.Payload,
		PreviousHash: prev,
		EventHash:    arg.EventHash,
		CreatedAt:    arg.CreatedAt,
	}
	m.events = append(m.events, row)
	return row, nil
}

func (m *memAuditStore) GetAuditChainHead(_ context.Context) (persistence.AuditChainHeadRow, error) {
	return m.head, nil
}

func (m *memAuditStore) ListAuditEvents(_ context.Context, arg persistence.ListAuditEventsParams) ([]persistence.AuditEventRow, error) {
	out := make([]persistence.AuditEventRow, 0)
	for _, ev := range m.events {
		if arg.CursorSeq != nil && ev.ChainSeq <= *arg.CursorSeq {
			continue
		}
		out = append(out, ev)
		if len(out) >= arg.Limit {
			break
		}
	}
	return out, nil
}

func (m *memAuditStore) ListAllAuditEventsOrdered(_ context.Context) ([]persistence.AuditEventRow, error) {
	cp := make([]persistence.AuditEventRow, len(m.events))
	copy(cp, m.events)
	return cp, nil
}

func (m *memAuditStore) RunInTx(_ context.Context, fn func(tx audit.ChainStore) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return fn(m)
}

func (m *memAuditStore) RunReadSnapshot(_ context.Context, fn func(rs audit.ReadStore) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return fn(m)
}

func TestAuditUnitHashTruncationTamperAndSafeLogging(t *testing.T) {
	t.Parallel()

	var logBuf bytes.Buffer
	logger := observability.NewLogger(observability.LoggerConfig{
		Writer: &logBuf,
		Format: observability.LogFormatJSON,
		Level:  slog.LevelInfo,
	})

	mem := newMemAuditStore()
	svc := audit.NewServiceWithStore(mem, logger)
	ctx := context.Background()

	// Provide sub-microsecond nanoseconds; audit service MUST truncate to time.Microsecond UTC before hashing.
	nanoTS := time.Date(2026, 11, 18, 12, 0, 0, 123456789, time.FixedZone("EST", -5*3600))
	resID := domain.MustNewID()
	ev1, err := svc.Append(ctx, audit.AppendInput{
		EventType:    "workspace.created",
		ResourceType: "workspace",
		ResourceID:   resID,
		Payload:      json.RawMessage(`{"secret_note":"must_not_be_logged"}`),
		CreatedAt:    nanoTS,
	})
	if err != nil {
		t.Fatalf("Append genesis: %v", err)
	}
	if ev1.PreviousHash != "" {
		t.Fatalf("expected empty genesis previous_hash, got %q", ev1.PreviousHash)
	}
	if ev1.CreatedAt.Nanosecond()%1000 != 0 {
		t.Fatalf("expected microsecond-truncated CreatedAt, got %s", ev1.CreatedAt.Format(time.RFC3339Nano))
	}
	if strings.Contains(logBuf.String(), "must_not_be_logged") {
		t.Fatalf("SafeHandler leaked payload content into logs: %s", logBuf.String())
	}

	// Append second event with empty payload (normalized to {}).
	ev2, err := svc.Append(ctx, audit.AppendInput{
		EventType:    "workspace.ready",
		ResourceType: "workspace",
		ResourceID:   resID,
	})
	if err != nil {
		t.Fatalf("Append second: %v", err)
	}
	if ev2.PreviousHash != ev1.EventHash {
		t.Fatalf("expected PreviousHash == ev1.EventHash")
	}

	res, err := svc.VerifyChain(ctx)
	if err != nil || res.EventCount != 2 || res.HeadHash != ev2.EventHash {
		t.Fatalf("VerifyChain failed: (%+v, %v)", res, err)
	}

	// Invalid cursor returns 400 BadRequest.
	_, err = svc.List(ctx, audit.ListFilter{Cursor: "not-base64!!!"})
	if !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for invalid cursor, got %v", err)
	}
	_, err = svc.List(ctx, audit.ListFilter{Limit: 501})
	if !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for limit > 500, got %v", err)
	}

	// Non-UUIDv7 ID is rejected with 400 BadRequest.
	_, err = svc.Append(ctx, audit.AppendInput{
		ID:           uuid.New(), // v4
		EventType:    "workspace.bad_id",
		ResourceType: "workspace",
		ResourceID:   resID,
	})
	if !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for UUIDv4 audit event ID, got %v", err)
	}

	// Tamper event 1 payload in store -> VerifyChain must fail.
	mem.events[0].Payload = json.RawMessage(`{"tampered":true}`)
	if _, err := svc.VerifyChain(ctx); err == nil {
		t.Fatalf("expected VerifyChain to detect tampered payload")
	}
}

func TestAuditConcurrentChainPaginationAndTamperPG17(t *testing.T) {
	pg := harness.StartPostgres(t)
	store, err := persistence.NewStore(pg.Pool())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	svc := audit.NewService(store, observability.NewLogger(observability.LoggerConfig{}))
	ctx := context.Background()

	// Seed 2 actors for filter testing.
	actor1, err := store.Upsert(ctx, domain.Principal{
		Kind:    domain.PrincipalKindHuman,
		Issuer:  "https://oidc.example",
		Subject: "audit-actor-1",
	})
	if err != nil {
		t.Fatalf("Upsert actor1: %v", err)
	}
	actor2, err := store.Upsert(ctx, domain.Principal{
		Kind:    domain.PrincipalKindHuman,
		Issuer:  "https://oidc.example",
		Subject: "audit-actor-2",
	})
	if err != nil {
		t.Fatalf("Upsert actor2: %v", err)
	}

	resA := domain.MustNewID()
	resB := domain.MustNewID()

	// 16 goroutines appending concurrently.
	const workers = 16
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			actor := &actor1.ID
			resID := resA
			evType := "workspace.created"
			if i%2 == 1 {
				actor = &actor2.ID
				resID = resB
				evType = "proposal.captured"
			}
			_, err := svc.Append(ctx, audit.AppendInput{
				EventType:    evType,
				ActorID:      actor,
				ResourceType: "workspace",
				ResourceID:   resID,
				Payload:      json.RawMessage(`{"seq_worker":` + string(rune('0'+i%10)) + `}`),
			})
			if err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent Append failed: %v", err)
	}

	// Non-UUIDv7 ID is rejected with 400 BadRequest in PG17 path as well.
	if _, err := svc.Append(ctx, audit.AppendInput{
		ID:           uuid.New(), // v4
		EventType:    "workspace.bad_id",
		ActorID:      &actor1.ID,
		ResourceType: "workspace",
		ResourceID:   resA,
		Payload:      json.RawMessage(`{"ok":false}`),
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for UUIDv4 audit event ID, got %v", err)
	}

	// PG17 JSONB numeric normalization round-trip cases: scientific notation, negative zero, trailing zero, large int64.
	numericPayloads := []struct {
		name    string
		payload string
	}{
		{name: "sci_pos", payload: `{"num":1e5}`},
		{name: "sci_neg", payload: `{"rate":1e-5}`},
		{name: "neg_zero", payload: `{"negzero":-0.0}`},
		{name: "trailing_zero", payload: `{"dec":1.2300}`},
		{name: "large_int64", payload: `{"big":9007199254740993}`},
	}
	for _, np := range numericPayloads {
		ev, err := svc.Append(ctx, audit.AppendInput{
			EventType:    "audit.numeric_probe." + np.name,
			ActorID:      &actor1.ID,
			ResourceType: "workspace",
			ResourceID:   resA,
			Payload:      json.RawMessage(np.payload),
		})
		if err != nil {
			t.Fatalf("Append %s (%s): %v", np.name, np.payload, err)
		}
		recomputed, err := domain.ComputeAuditEventHash(ev.PreviousHash, ev)
		if err != nil || recomputed != ev.EventHash {
			t.Fatalf("returned event hash mismatch for %s: got %s, recomputed %s (payload=%s, err=%v)", np.name, ev.EventHash, recomputed, string(ev.Payload), err)
		}
	}

	verifyRes, err := svc.VerifyChain(ctx)
	if err != nil {
		t.Fatalf("VerifyChain after 16 concurrent + 5 numeric appends: %v", err)
	}
	if verifyRes.EventCount != workers+int64(len(numericPayloads)) {
		t.Fatalf("expected EventCount=%d, got %d", workers+len(numericPayloads), verifyRes.EventCount)
	}

	// Verify filtered cursor pagination across resA (8 + 5 = 13 events) with limit=3.
	var collected []uuid.UUID
	cursor := ""
	for {
		page, err := svc.List(ctx, audit.ListFilter{
			ResourceType: "workspace",
			ResourceID:   &resA,
			ActorID:      &actor1.ID,
			Cursor:       cursor,
			Limit:        3,
		})
		if err != nil {
			t.Fatalf("List page cursor=%q: %v", cursor, err)
		}
		for _, ev := range page.Events {
			collected = append(collected, ev.ID)
			recomputed, err := domain.ComputeAuditEventHash(ev.PreviousHash, ev)
			if err != nil || recomputed != ev.EventHash {
				t.Fatalf("readback hash mismatch for %s: got %s, recomputed %s (err=%v)", ev.ID, ev.EventHash, recomputed, err)
			}
		}
		if !page.HasMore {
			break
		}
		if page.NextCursor == "" {
			t.Fatalf("HasMore=true with empty NextCursor")
		}
		cursor = page.NextCursor
	}
	if len(collected) != 8+len(numericPayloads) {
		t.Fatalf("expected %d filtered events across paginated pages, got %d", 8+len(numericPayloads), len(collected))
	}

	// Tamper a middle row in PostgreSQL and assert VerifyChain catches it.
	if _, err := pg.Pool().Exec(ctx, `UPDATE audit_events SET payload = '{"tampered":true}'::jsonb WHERE chain_seq = 5`); err != nil {
		t.Fatalf("tamper SQL update: %v", err)
	}
	if _, err := svc.VerifyChain(ctx); err == nil {
		t.Fatalf("expected VerifyChain to fail after SQL payload tamper")
	}
}
