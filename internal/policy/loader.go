package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/timreynolds/custodian/internal/domain"
)

// LoadBundleFile reads and compiles a single YAML or JSON policy bundle file.
func (e *Engine) LoadBundleFile(path string) (*CompiledBundle, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy bundle %q: %w", path, err)
	}
	compiled, errs := e.Compile(raw)
	if len(errs) > 0 {
		return nil, fmt.Errorf("compile policy bundle %q: [%s] %s", path, errs[0].Code, errs[0].Message)
	}
	return compiled, nil
}

// LoadDir loads and compiles all *.yaml and *.yml policy bundles from dir in sorted filename order.
// Failing to compile any bundle fails closed with an error.
func (e *Engine) LoadDir(dir string) ([]*CompiledBundle, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read policy directory %q: %w", dir, err)
	}

	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			files = append(files, name)
		}
	}
	sort.Strings(files)

	if len(files) == 0 {
		return nil, fmt.Errorf("policy directory %q contains no *.yaml/*.yml bundles", dir)
	}

	bundles := make([]*CompiledBundle, 0, len(files))
	for _, name := range files {
		cb, err := e.LoadBundleFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		bundles = append(bundles, cb)
	}
	return bundles, nil
}

// PartitionByScope splits compiled bundles into ORG-scoped and REPO-scoped lists.
// Bundles without an explicit metadata.scope default to ORG (baseline) scope.
func PartitionByScope(bundles []*CompiledBundle) (orgBundles, repoBundles []*CompiledBundle) {
	for _, b := range bundles {
		if b == nil {
			continue
		}
		scope := b.Scope
		if !scope.IsValid() {
			scope = b.Bundle.Metadata.Scope
		}
		if scope == domain.PolicyScopeRepo {
			repoBundles = append(repoBundles, b)
		} else {
			orgBundles = append(orgBundles, b)
		}
	}
	return orgBundles, repoBundles
}
