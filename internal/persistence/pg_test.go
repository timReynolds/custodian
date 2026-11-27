package persistence_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/persistence"
)

var testPGSeq atomic.Uint64

func startPG17ForPersistenceTest(t *testing.T) (string, *pgxpool.Pool) {
	t.Helper()
	if testing.Short() && os.Getenv("CUSTODIAN_TEST_FORCE_DOCKER") != "1" {
		t.Skip("skipping PG17 integration test under -short")
	}

	if dsn := strings.TrimSpace(os.Getenv("CUSTODIAN_TEST_DSN")); dsn != "" {
		pool, err := persistence.NewPool(context.Background(), dsn, persistence.DefaultPoolConfig())
		if err != nil {
			t.Fatalf("connect CUSTODIAN_TEST_DSN: %v", err)
		}
		t.Cleanup(pool.Close)
		return dsn, pool
	}

	if err := exec.Command("docker", "info").Run(); err != nil {
		if os.Getenv("CUSTODIAN_TEST_ALLOW_DOCKER_SKIP") == "1" {
			t.Skipf("docker unavailable: %v", err)
		}
		t.Fatalf("docker unavailable: %v", err)
	}

	name := fmt.Sprintf("custodian-m1-persist-%d-%d", os.Getpid(), testPGSeq.Add(1))
	runCmd := exec.Command("docker", "run", "-d", "--rm",
		"--name", name,
		"-e", "POSTGRES_USER=custodian",
		"-e", "POSTGRES_PASSWORD=custodian",
		"-e", "POSTGRES_DB=custodian",
		"-p", "127.0.0.1::5432",
		"postgres:17-alpine",
		"-c", "fsync=off", "-c", "synchronous_commit=off", "-c", "full_page_writes=off", "-c", "max_connections=200",
	)
	var out, stderr bytes.Buffer
	runCmd.Stdout = &out
	runCmd.Stderr = &stderr
	if err := runCmd.Run(); err != nil {
		t.Fatalf("docker run: %v (%s)", err, stderr.String())
	}
	cid := strings.TrimSpace(out.String())
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", "-v", cid).Run()
	})

	portOut, err := exec.Command("docker", "port", cid, "5432/tcp").CombinedOutput()
	if err != nil {
		t.Fatalf("docker port: %v (%s)", err, string(portOut))
	}
	line := strings.TrimSpace(strings.Split(strings.TrimSpace(string(portOut)), "\n")[0])
	_, portStr, err := net.SplitHostPort(line)
	if err != nil {
		t.Fatalf("split host port %q: %v", line, err)
	}
	portNum, err := strconv.Atoi(portStr)
	if err != nil || portNum <= 0 || portNum == 5432 {
		t.Fatalf("invalid ephemeral port %q", portStr)
	}

	dsn := fmt.Sprintf("postgres://custodian:custodian@127.0.0.1:%s/custodian?sslmode=disable", portStr)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		pool, err := persistence.NewPool(ctx, dsn, persistence.DefaultPoolConfig())
		cancel()
		if err == nil {
			t.Cleanup(pool.Close)
			return dsn, pool
		}
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for postgres container %s", cid)
	return "", nil
}

func TestMigrationsUpDownAndSchemaVerificationPG17(t *testing.T) {
	dsn, pool := startPG17ForPersistenceTest(t)
	ctx := context.Background()

	if err := persistence.MigrateUp(ctx, dsn); err != nil {
		t.Fatalf("MigrateUp(dsn): %v", err)
	}
	// Idempotent re-run should succeed with no error.
	if err := persistence.MigrateUpPool(ctx, pool); err != nil {
		t.Fatalf("MigrateUpPool idempotent: %v", err)
	}

	expectedTables := []string{
		"principals", "repositories", "workspaces", "artifacts", "proposals",
		"scan_runs", "findings", "model_assessments", "policy_bundles", "policy_decisions",
		"approvals", "publications", "operations", "audit_events", "outbox_events",
		"idempotency_keys", "approval_requirements", "publication_attempts", "audit_chain_head",
		"push_sessions", "push_approval_releases", "ip_fingerprint_corpora", "ip_fingerprints",
	}

	rows, err := pool.Query(ctx, `
		SELECT table_name
		FROM information_schema.tables
		WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
	`)
	if err != nil {
		t.Fatalf("query tables: %v", err)
	}
	tableSet := make(map[string]bool)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan table name: %v", err)
		}
		tableSet[name] = true
	}
	rows.Close()

	for _, tbl := range expectedTables {
		if !tableSet[tbl] {
			t.Fatalf("missing table %q after MigrateUp", tbl)
		}
	}

	idxRows, err := pool.Query(ctx, `
		SELECT indexname FROM pg_indexes WHERE schemaname = 'public'
	`)
	if err != nil {
		t.Fatalf("query indexes: %v", err)
	}
	idxSet := make(map[string]bool)
	for idxRows.Next() {
		var name string
		if err := idxRows.Scan(&name); err != nil {
			t.Fatalf("scan index name: %v", err)
		}
		idxSet[name] = true
	}
	idxRows.Close()

	for _, idx := range []string{
		"idx_proposals_workspace", "idx_findings_scan", "idx_operations_ready", "idx_audit_resource",
		"idx_push_sessions_principal", "idx_push_approval_releases_active_binding", "idx_ip_fingerprints_lookup",
	} {
		if !idxSet[idx] {
			t.Fatalf("missing Spec §10 index %q", idx)
		}
	}

	var count int64
	if err := pool.QueryRow(ctx, `SELECT event_count FROM audit_chain_head WHERE chain_id = 'default'`).Scan(&count); err != nil {
		t.Fatalf("check audit_chain_head seed: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected initial event_count=0, got %d", count)
	}

	// Migrate Down -> verify all 19 tables removed cleanly.
	if err := persistence.MigrateDownPool(ctx, pool); err != nil {
		t.Fatalf("MigrateDownPool: %v", err)
	}
	var remaining int
	if err := pool.QueryRow(ctx, `
		SELECT count(*)
		FROM information_schema.tables
		WHERE table_schema = 'public'
		  AND table_type = 'BASE TABLE'
		  AND table_name <> 'schema_migrations'
	`).Scan(&remaining); err != nil {
		t.Fatalf("count remaining tables: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("expected 0 domain tables after MigrateDown, found %d", remaining)
	}

	// Re-apply MigrateUp cleanly.
	if err := persistence.MigrateUpPool(ctx, pool); err != nil {
		t.Fatalf("MigrateUpPool after down: %v", err)
	}
	var restored int
	if err := pool.QueryRow(ctx, `
		SELECT count(*)
		FROM information_schema.tables
		WHERE table_schema = 'public'
		  AND table_type = 'BASE TABLE'
		  AND table_name <> 'schema_migrations'
	`).Scan(&restored); err != nil {
		t.Fatalf("count restored tables: %v", err)
	}
	if restored != 23 {
		t.Fatalf("expected 23 domain tables after re-up, got %d", restored)
	}

	// Verify repositories.full_name CHECK rejects malformed names and accepts "org/repo".
	for _, badName := range []string{"owner/", "/repo", "a/b/c", "org/re po", "noslash"} {
		_, err := pool.Exec(ctx, `
			INSERT INTO repositories (id, github_repository_id, github_installation_id, full_name, classification, enabled)
			VALUES ($1, $2, 1, $3, 'PUBLIC', true)
		`, domain.MustNewID(), time.Now().UnixNano(), badName)
		if err == nil || !errors.Is(persistence.MapError(err), domain.ErrBadRequest) {
			t.Fatalf("expected repositories.full_name CHECK failure for %q, got %v", badName, err)
		}
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO repositories (id, github_repository_id, github_installation_id, full_name, classification, enabled)
		VALUES ($1, 88888, 1, 'org/repo', 'PUBLIC', true)
	`, domain.MustNewID()); err != nil {
		t.Fatalf("expected valid full_name 'org/repo' to succeed, got %v", err)
	}
}

func TestPrincipalStoreAndIdempotencyKeysPG17(t *testing.T) {
	dsn, pool := startPG17ForPersistenceTest(t)
	ctx := context.Background()
	if err := persistence.MigrateUp(ctx, dsn); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}

	store, err := persistence.NewStore(pool)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	// Verify PrincipalStore interface on *Store and *Tx.
	var ps domain.PrincipalStore = store
	p, err := ps.Upsert(ctx, domain.Principal{
		Kind:          domain.PrincipalKindHuman,
		Issuer:        "https://oidc.example",
		Subject:       "user-123",
		DisplayName:   "Alice",
		VerifiedEmail: "alice@example.com",
	})
	if err != nil {
		t.Fatalf("Upsert principal: %v", err)
	}
	if !domain.IsUUIDv7(p.ID) {
		t.Fatalf("expected UUIDv7 principal ID, got %s", p.ID)
	}

	// Upsert again with same issuer+subject updates display_name without duplicating row.
	p2, err := ps.Upsert(ctx, domain.Principal{
		Kind:        domain.PrincipalKindHuman,
		Issuer:      "https://oidc.example",
		Subject:     "user-123",
		DisplayName: "Alice Updated",
	})
	if err != nil {
		t.Fatalf("Upsert update principal: %v", err)
	}
	if p2.ID != p.ID || p2.DisplayName != "Alice Updated" || p2.VerifiedEmail != "alice@example.com" {
		t.Fatalf("unexpected updated principal: %+v", p2)
	}

	gotByIS, err := ps.GetByIssuerSubject(ctx, "https://oidc.example", "user-123")
	if err != nil || gotByIS.ID != p.ID {
		t.Fatalf("GetByIssuerSubject: got (%+v, %v)", gotByIS, err)
	}
	_, err = ps.GetByID(ctx, domain.MustNewID())
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing principal, got %v", err)
	}

	// Idempotency lifecycle: Reserve -> in-progress 409 -> Finalize -> replay -> mismatch 409 -> stale takeover.
	now := time.Now().UTC().Truncate(time.Microsecond)
	reqHash := domain.SHA256Hex([]byte(`{"repo":"1"}`))
	otherHash := domain.SHA256Hex([]byte(`{"repo":"2"}`))

	res1, err := store.ReserveIdempotencyKey(ctx, persistence.IdempotencyReserveInput{
		PrincipalID:    p.ID,
		Method:         "POST",
		Route:          "/v1/workspaces",
		IdempotencyKey: "key-1",
		RequestHash:    reqHash,
		LockTTL:        30 * time.Second,
		TTL:            1 * time.Hour,
		Now:            now,
	})
	if err != nil {
		t.Fatalf("ReserveIdempotencyKey fresh: %v", err)
	}
	if !res1.Acquired || res1.Replay {
		t.Fatalf("expected Acquired=true, Replay=false, got %+v", res1)
	}

	// Active IN_PROGRESS returns 409 Conflict.
	_, err = store.ReserveIdempotencyKey(ctx, persistence.IdempotencyReserveInput{
		PrincipalID:    p.ID,
		Method:         "POST",
		Route:          "/v1/workspaces",
		IdempotencyKey: "key-1",
		RequestHash:    reqHash,
		LockTTL:        30 * time.Second,
		Now:            now.Add(5 * time.Second),
	})
	if !errors.Is(err, domain.ErrConflict) || domain.HTTPStatusFromError(err) != 409 {
		t.Fatalf("expected 409 Conflict for in-progress key, got %v", err)
	}

	// Finalize key with expected lock timestamp.
	body := json.RawMessage(`{"workspace_id":"` + uuid.NewString() + `"}`)
	_, err = store.FinalizeIdempotencyKey(ctx, persistence.FinalizeIdempotencyParams{
		PrincipalID:         p.ID,
		Method:              "POST",
		Route:               "/v1/workspaces",
		IdempotencyKey:      "key-1",
		ExpectedLockedUntil: res1.Record.LockedUntil,
		ResponseStatus:      202,
		ResponseHeaders:     json.RawMessage(`{"content-type":"application/json"}`),
		ResponseBody:        body,
		CompletedAt:         now.Add(1 * time.Second),
		ExpiresAt:           now.Add(1 * time.Hour),
	})
	if err != nil {
		t.Fatalf("FinalizeIdempotencyKey: %v", err)
	}

	// Replay with matching hash returns cached response.
	replay, err := store.ReserveIdempotencyKey(ctx, persistence.IdempotencyReserveInput{
		PrincipalID:    p.ID,
		Method:         "POST",
		Route:          "/v1/workspaces",
		IdempotencyKey: "key-1",
		RequestHash:    reqHash,
		Now:            now.Add(10 * time.Second),
	})
	if err != nil {
		t.Fatalf("ReserveIdempotencyKey replay: %v", err)
	}
	if replay.Acquired || !replay.Replay || *replay.Record.ResponseStatus != 202 {
		t.Fatalf("expected Replay=true status=202, got %+v", replay)
	}

	// Different payload hash returns 409 Conflict.
	_, err = store.ReserveIdempotencyKey(ctx, persistence.IdempotencyReserveInput{
		PrincipalID:    p.ID,
		Method:         "POST",
		Route:          "/v1/workspaces",
		IdempotencyKey: "key-1",
		RequestHash:    otherHash,
		Now:            now.Add(10 * time.Second),
	})
	if !errors.Is(err, domain.ErrConflict) || domain.HTTPStatusFromError(err) != 409 {
		t.Fatalf("expected 409 Conflict on payload mismatch, got %v", err)
	}

	// Stale lock takeover when locked_until <= now + fencing stale Worker 1 FinalizeIdempotencyKey.
	resWorker1, err := store.ReserveIdempotencyKey(ctx, persistence.IdempotencyReserveInput{
		PrincipalID:    p.ID,
		Method:         "POST",
		Route:          "/v1/workspaces",
		IdempotencyKey: "stale-key",
		RequestHash:    reqHash,
		LockTTL:        5 * time.Second,
		TTL:            1 * time.Hour,
		Now:            now,
	})
	if err != nil {
		t.Fatalf("Reserve stale-key: %v", err)
	}
	taken, err := store.ReserveIdempotencyKey(ctx, persistence.IdempotencyReserveInput{
		PrincipalID:    p.ID,
		Method:         "POST",
		Route:          "/v1/workspaces",
		IdempotencyKey: "stale-key",
		RequestHash:    reqHash,
		LockTTL:        30 * time.Second,
		TTL:            1 * time.Hour,
		Now:            now.Add(6 * time.Second),
	})
	if err != nil || !taken.Acquired || taken.Replay {
		t.Fatalf("expected stale lock takeover Acquired=true, got (%+v, %v)", taken, err)
	}

	// Stale Worker 1 fails to finalize BEFORE Worker 2 finalizes (409 Conflict).
	_, err = store.FinalizeIdempotencyKey(ctx, persistence.FinalizeIdempotencyParams{
		PrincipalID:         p.ID,
		Method:              "POST",
		Route:               "/v1/workspaces",
		IdempotencyKey:      "stale-key",
		ExpectedLockedUntil: resWorker1.Record.LockedUntil,
		ResponseStatus:      500,
		ResponseBody:        json.RawMessage(`{"owner":"stale-worker1"}`),
		CompletedAt:         now.Add(7 * time.Second),
		ExpiresAt:           now.Add(1 * time.Hour),
	})
	if !errors.Is(err, domain.ErrConflict) || domain.HTTPStatusFromError(err) != 409 {
		t.Fatalf("expected 409 Conflict for stale Worker 1 finalize before Worker 2 completes, got %v", err)
	}

	// Worker 2 finalizes with 201.
	_, err = store.FinalizeIdempotencyKey(ctx, persistence.FinalizeIdempotencyParams{
		PrincipalID:         p.ID,
		Method:              "POST",
		Route:               "/v1/workspaces",
		IdempotencyKey:      "stale-key",
		ExpectedLockedUntil: taken.Record.LockedUntil,
		ResponseStatus:      201,
		ResponseBody:        json.RawMessage(`{"owner":"worker2"}`),
		CompletedAt:         now.Add(8 * time.Second),
		ExpiresAt:           now.Add(1 * time.Hour),
	})
	if err != nil {
		t.Fatalf("Worker 2 FinalizeIdempotencyKey: %v", err)
	}

	// Stale Worker 1 fails to overwrite Worker 2's 201 COMPLETED response (409 Conflict).
	_, err = store.FinalizeIdempotencyKey(ctx, persistence.FinalizeIdempotencyParams{
		PrincipalID:         p.ID,
		Method:              "POST",
		Route:               "/v1/workspaces",
		IdempotencyKey:      "stale-key",
		ExpectedLockedUntil: resWorker1.Record.LockedUntil,
		ResponseStatus:      500,
		ResponseBody:        json.RawMessage(`{"owner":"stale-worker1"}`),
		CompletedAt:         now.Add(9 * time.Second),
		ExpiresAt:           now.Add(1 * time.Hour),
	})
	if !errors.Is(err, domain.ErrConflict) || domain.HTTPStatusFromError(err) != 409 {
		t.Fatalf("expected 409 Conflict for stale Worker 1 finalize after Worker 2 completes, got %v", err)
	}
	// Verify Worker 2's 201 response is preserved.
	preserved, err := store.GetIdempotencyKey(ctx, p.ID, "POST", "/v1/workspaces", "stale-key")
	if err != nil || preserved.Status != "COMPLETED" || preserved.ResponseStatus == nil || *preserved.ResponseStatus != 201 {
		t.Fatalf("expected preserved 201 COMPLETED response, got (%+v, %v)", preserved, err)
	}

	// Finalize on truly missing key returns 404 NotFound.
	_, err = store.FinalizeIdempotencyKey(ctx, persistence.FinalizeIdempotencyParams{
		PrincipalID:    p.ID,
		Method:         "POST",
		Route:          "/v1/workspaces",
		IdempotencyKey: "nonexistent-key",
		ResponseStatus: 200,
	})
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing key finalize, got %v", err)
	}

	// Reaper TOCTOU stress: concurrent DeleteExpiredIdempotencyKeys + ReserveIdempotencyKey never returns 404.
	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("reaper-race-%d", i)
		_, err := store.ReserveIdempotencyKey(ctx, persistence.IdempotencyReserveInput{
			PrincipalID:    p.ID,
			Method:         "POST",
			Route:          "/v1/workspaces",
			IdempotencyKey: key,
			RequestHash:    reqHash,
			LockTTL:        1 * time.Second,
			TTL:            2 * time.Second,
			Now:            now,
		})
		if err != nil {
			t.Fatalf("seed expired key %s: %v", key, err)
		}
		var wg sync.WaitGroup
		errs := make(chan error, 4)
		wg.Add(2)
		go func() {
			defer wg.Done()
			if _, err := store.DeleteExpiredIdempotencyKeys(ctx, now.Add(5*time.Second)); err != nil {
				errs <- err
			}
		}()
		go func() {
			defer wg.Done()
			res, err := store.ReserveIdempotencyKey(ctx, persistence.IdempotencyReserveInput{
				PrincipalID:    p.ID,
				Method:         "POST",
				Route:          "/v1/workspaces",
				IdempotencyKey: key,
				RequestHash:    reqHash,
				LockTTL:        30 * time.Second,
				TTL:            1 * time.Hour,
				Now:            now.Add(5 * time.Second),
			})
			if err != nil {
				errs <- err
				return
			}
			if !res.Acquired {
				errs <- fmt.Errorf("expected Acquired=true for %s", key)
			}
		}()
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatalf("reaper TOCTOU race error for %s: %v", key, err)
		}
	}

	// DeleteExpired cleans expired rows.
	deleted, err := store.DeleteExpiredIdempotencyKeys(ctx, now.Add(2*time.Hour))
	if err != nil || deleted < 2 {
		t.Fatalf("expected >= 2 expired keys deleted, got (%d, %v)", deleted, err)
	}
}
