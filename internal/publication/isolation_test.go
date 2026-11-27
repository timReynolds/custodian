package publication_test

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func goBinary() string {
	if p, err := exec.LookPath("go"); err == nil {
		return p
	}
	return filepath.Join(runtime.GOROOT(), "bin", "go")
}

func TestPublisherDependencyIsolation(t *testing.T) {
	forbiddenRuntime := []string{
		"github.com/timreynolds/custodian/internal/inspection",
		"github.com/timreynolds/custodian/internal/decisions",
		"github.com/timreynolds/custodian/internal/snapshots",
		"github.com/timreynolds/custodian/internal/archive",
		"github.com/timreynolds/custodian/internal/auth",
		"github.com/timreynolds/custodian/internal/identity",
		"github.com/timreynolds/custodian/internal/policy",
		"github.com/timreynolds/custodian/internal/git/reconstruct",
		"github.com/timreynolds/custodian/internal/git/checkout",
		"github.com/timreynolds/custodian/internal/gitgateway",
		"github.com/google/cel-go",
		"golang.org/x/crypto/ssh",
	}
	forbiddenExact := "github.com/timreynolds/custodian/internal/github"

	goBin := goBinary()
	cmd := exec.Command(goBin, "list", "-deps", "../../cmd/custodian-publisher", "../../internal/publication", "../../internal/git/publish")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("go list -deps failed: %v (%s)", err, stderr.String())
	}

	for _, line := range strings.Split(stdout.String(), "\n") {
		pkg := strings.TrimSpace(line)
		if pkg == "" {
			continue
		}
		if pkg == forbiddenExact {
			t.Fatalf("forbidden root github package in publisher deps: %s", pkg)
		}
		for _, prefix := range forbiddenRuntime {
			if pkg == prefix || strings.HasPrefix(pkg, prefix+"/") {
				t.Fatalf("forbidden dependency %s in publisher deps", pkg)
			}
		}
	}

	testCmd := exec.Command(goBin, "list", "-test", "-deps", "../../cmd/custodian-publisher", "../../internal/publication")
	var testOut, testErr bytes.Buffer
	testCmd.Stdout = &testOut
	testCmd.Stderr = &testErr
	if err := testCmd.Run(); err != nil {
		t.Fatalf("go list -test -deps failed: %v (%s)", err, testErr.String())
	}
	for _, line := range strings.Split(testOut.String(), "\n") {
		pkg := strings.TrimSpace(line)
		if pkg == "" {
			continue
		}
		for _, prefix := range []string{
			"github.com/timreynolds/custodian/internal/snapshots",
			"github.com/timreynolds/custodian/internal/harness",
		} {
			if pkg == prefix || strings.HasPrefix(pkg, prefix+"/") {
				t.Fatalf("forbidden test dependency %s in publisher test deps", pkg)
			}
		}
	}
}
