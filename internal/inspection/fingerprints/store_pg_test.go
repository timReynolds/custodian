package fingerprints_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/inspection/fingerprints"
	"github.com/timreynolds/custodian/internal/persistence"
)

var fpPGSeq atomic.Uint64

func startPG17ForFingerprintTest(t *testing.T) *pgxpool.Pool {
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
		if err := persistence.MigrateUpPool(context.Background(), pool); err != nil {
			t.Fatalf("MigrateUpPool: %v", err)
		}
		return pool
	}

	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skipf("docker unavailable: %v", err)
	}

	name := fmt.Sprintf("custodian-m3-fp-%d-%d", os.Getpid(), fpPGSeq.Add(1))
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
	if err != nil || portNum <= 0 {
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
			if err := persistence.MigrateUpPool(context.Background(), pool); err != nil {
				t.Fatalf("MigrateUpPool: %v", err)
			}
			return pool
		}
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for postgres container %s", cid)
	return nil
}

func TestPG17PersistenceStoreMultiRowNilFilePathHashAndIndexerReindex(t *testing.T) {
	pool := startPG17ForFingerprintTest(t)
	ctx := context.Background()
	store, err := persistence.NewStore(pool)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	// 1. Multi-row UpsertIPFingerprintsBatch with empty FilePathHash (nil *string), mixed nil/non-nil,
	// Go-side dedup, and cross-batch UNIQUE NULLS NOT DISTINCT conflict update.
	nullCorpus, err := store.CreateIPFingerprintCorpus(ctx, persistence.CreateIPFingerprintCorpusParams{
		Name:           "pg17-null-filepath-test",
		Classification: domain.ClassificationConfidential,
		Status:         domain.IPCorpusStatusReady,
	})
	if err != nil {
		t.Fatalf("CreateIPFingerprintCorpus: %v", err)
	}

	h1 := domain.SHA256Hex([]byte("row1"))
	h2 := domain.SHA256Hex([]byte("row2"))
	h3 := domain.SHA256Hex([]byte("row3"))
	fpPath := domain.SHA256Hex([]byte("src/file.go"))

	affected, err := store.UpsertIPFingerprintsBatch(ctx, []persistence.InsertIPFingerprintParams{
		{CorpusID: nullCorpus.ID, Layer: domain.FingerprintLayerL1ExactChunk, FingerprintHash: h1, FilePathHash: "", Metadata: map[string]any{"chunk_bytes": 100}},
		{CorpusID: nullCorpus.ID, Layer: domain.FingerprintLayerL1ExactChunk, FingerprintHash: h1, FilePathHash: "", Metadata: map[string]any{"chunk_bytes": 150}}, // duplicate nil key in batch
		{CorpusID: nullCorpus.ID, Layer: domain.FingerprintLayerL2WinnowKGram, FingerprintHash: "0123456789abcdef", FilePathHash: "", Metadata: map[string]any{"winnow_k": 25}},
		{CorpusID: nullCorpus.ID, Layer: domain.FingerprintLayerL1ExactChunk, FingerprintHash: h2, FilePathHash: fpPath, Metadata: map[string]any{"chunk_bytes": 200}},
		{CorpusID: nullCorpus.ID, Layer: domain.FingerprintLayerL1ExactChunk, FingerprintHash: h3, FilePathHash: "", Metadata: map[string]any{"chunk_bytes": 300}},
	})
	if err != nil {
		t.Fatalf("multi-row UpsertIPFingerprintsBatch with nil FilePathHash failed: %v", err)
	}
	if affected != 4 {
		t.Fatalf("expected 4 unique rows affected, got %d", affected)
	}

	// Cross-batch upsert on identical nil FilePathHash + nil ChunkIndex must conflict-update without creating duplicate row.
	if _, err := store.UpsertIPFingerprintsBatch(ctx, []persistence.InsertIPFingerprintParams{
		{CorpusID: nullCorpus.ID, Layer: domain.FingerprintLayerL1ExactChunk, FingerprintHash: h1, FilePathHash: "", Metadata: map[string]any{"chunk_bytes": 175}},
	}); err != nil {
		t.Fatalf("cross-batch upsert nil FilePathHash failed: %v", err)
	}
	cnt, err := store.CountIPFingerprintsByCorpus(ctx, nullCorpus.ID)
	if err != nil || cnt != 4 {
		t.Fatalf("expected CountIPFingerprintsByCorpus == 4 after UNIQUE NULLS NOT DISTINCT conflict update, got %d (err=%v)", cnt, err)
	}

	// 2. End-to-end CorpusIndexer + NewPersistenceTxRunner(store) + Engine.Analyze against real PG17.
	restCorpus, err := store.CreateIPFingerprintCorpus(ctx, persistence.CreateIPFingerprintCorpusParams{
		Name:           "pg17-restricted-engine",
		Classification: domain.ClassificationRestricted,
	})
	if err != nil {
		t.Fatalf("CreateIPFingerprintCorpus restricted: %v", err)
	}

	idx := fingerprints.NewCorpusIndexer(store, fingerprints.NewPersistenceTxRunner(store))
	propBytes := readFixture(t, "corpora/restricted/proprietary_engine.go")
	res1, err := idx.Index(ctx, fingerprints.IndexRequest{
		CorpusID: restCorpus.ID,
		Files: []fingerprints.CorpusFile{
			{Path: "engine/proprietary_engine.go", Content: propBytes},
		},
	})
	if err != nil {
		t.Fatalf("PG17 Index failed: %v", err)
	}
	if res1.Corpus.Status != domain.IPCorpusStatusReady || res1.FingerprintCount == 0 {
		t.Fatalf("unexpected PG17 Index result: %+v", res1)
	}

	// Idempotent reindex skips; Force reindex preserves identical count.
	res2, err := idx.Index(ctx, fingerprints.IndexRequest{
		CorpusID: restCorpus.ID,
		Force:    true,
		Files: []fingerprints.CorpusFile{
			{Path: "engine/proprietary_engine.go", Content: propBytes},
		},
	})
	if err != nil || res2.FingerprintCount != res1.FingerprintCount {
		t.Fatalf("expected identical PG17 count on Force reindex: %+v vs %+v (err=%v)", res2, res1, err)
	}

	eng := fingerprints.NewEngine(fingerprints.EngineConfig{Store: store, RequireStore: true})
	findings, cov, err := runEngineOnFiles(t, eng, map[string][]byte{
		"stripped.go": readFixture(t, "payloads/stripped_header_engine.go"),
	}, "")
	if err != nil || !cov.Complete {
		t.Fatalf("PG17 Engine.Analyze failed: cov=%+v err=%v", cov, err)
	}
	if !hasRule(findings, "ip.l2.winnow-kgram") || !hasRule(findings, "ip.l3.header-stripped") {
		t.Fatalf("expected L2 + L3b header-stripped via PG17 store, got %+v", findings)
	}
}
