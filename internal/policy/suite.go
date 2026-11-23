package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/timreynolds/custodian/internal/domain"
)

// TestSuite represents a declarative YAML policy test suite (`kind: PolicyTestSuite`).
type TestSuite struct {
	APIVersion    string            `yaml:"apiVersion" json:"apiVersion"`
	Kind          string            `yaml:"kind" json:"kind"`
	Metadata      TestSuiteMetadata `yaml:"metadata" json:"metadata"`
	Bundle        string            `yaml:"bundle,omitempty" json:"bundle,omitempty"`
	OrgBundle     string            `yaml:"org_bundle,omitempty" json:"org_bundle,omitempty"`
	BundleYAML    string            `yaml:"bundle_yaml,omitempty" json:"bundle_yaml,omitempty"`
	OrgBundleYAML string            `yaml:"org_bundle_yaml,omitempty" json:"org_bundle_yaml,omitempty"`
	Cases         []TestCase        `yaml:"cases" json:"cases"`
}

// TestSuiteMetadata names the test suite.
type TestSuiteMetadata struct {
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

// TestCase describes one policy evaluation scenario and expected outcome.
type TestCase struct {
	Name          string          `yaml:"name" json:"name"`
	Stage         string          `yaml:"stage" json:"stage"`
	Bundle        string          `yaml:"bundle,omitempty" json:"bundle,omitempty"`
	OrgBundle     string          `yaml:"org_bundle,omitempty" json:"org_bundle,omitempty"`
	BundleYAML    string          `yaml:"bundle_yaml,omitempty" json:"bundle_yaml,omitempty"`
	OrgBundleYAML string          `yaml:"org_bundle_yaml,omitempty" json:"org_bundle_yaml,omitempty"`
	Input         map[string]any  `yaml:"input" json:"input"`
	Expect        TestExpectation `yaml:"expect" json:"expect"`
}

// TestExpectation declares assertions checked against the EvalResult of a TestCase.
type TestExpectation struct {
	Effect           domain.PolicyEffect `yaml:"effect" json:"effect"`
	MatchedRules     []string            `yaml:"matched_rules,omitempty" json:"matched_rules,omitempty"`
	AbsentRules      []string            `yaml:"absent_rules,omitempty" json:"absent_rules,omitempty"`
	Obligations      []RuleObligation    `yaml:"obligations,omitempty" json:"obligations,omitempty"`
	ExpectTraceError bool                `yaml:"expect_trace_error,omitempty" json:"expect_trace_error,omitempty"`
}

// TestCaseResult records the outcome of running a single TestCase.
type TestCaseResult struct {
	Name          string              `json:"name"`
	Passed        bool                `json:"passed"`
	FailureReason string              `json:"failure_reason,omitempty"`
	ActualEffect  domain.PolicyEffect `json:"actual_effect,omitempty"`
	EvalResult    *EvalResult         `json:"eval_result,omitempty"`
}

// TestSuiteReport summarizes the execution of one PolicyTestSuite.
type TestSuiteReport struct {
	SuiteName string           `json:"suite_name"`
	FilePath  string           `json:"file_path,omitempty"`
	Passed    int              `json:"passed"`
	Failed    int              `json:"failed"`
	Cases     []TestCaseResult `json:"cases"`
}

// AllPassed reports whether every case in the suite passed.
func (r TestSuiteReport) AllPassed() bool {
	return r.Failed == 0 && len(r.Cases) > 0
}

// TestDirReport aggregates results across all suite files in a directory.
type TestDirReport struct {
	Dir    string            `json:"dir"`
	Passed int               `json:"passed"`
	Failed int               `json:"failed"`
	Suites []TestSuiteReport `json:"suites"`
}

// AllPassed reports whether at least one suite ran and every case in every suite passed.
func (r TestDirReport) AllPassed() bool {
	return r.Failed == 0 && r.Passed > 0 && len(r.Suites) > 0
}

// FormatText renders a human-readable summary suitable for `custodian-policy test`.
func (r TestDirReport) FormatText() string {
	var sb strings.Builder
	for _, s := range r.Suites {
		fmt.Fprintf(&sb, "SUITE %s (%s): %d passed, %d failed\n", s.SuiteName, s.FilePath, s.Passed, s.Failed)
		for _, c := range s.Cases {
			status := "PASS"
			if !c.Passed {
				status = "FAIL"
			}
			fmt.Fprintf(&sb, "  [%s] %s (effect=%s)", status, c.Name, c.ActualEffect)
			if c.FailureReason != "" {
				fmt.Fprintf(&sb, ": %s", c.FailureReason)
			}
			sb.WriteByte('\n')
		}
	}
	fmt.Fprintf(&sb, "TOTAL: %d passed, %d failed\n", r.Passed, r.Failed)
	return sb.String()
}

// FormatJSON renders the directory report as formatted JSON.
func (r TestDirReport) FormatJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// ParseTestSuite strictly decodes a single-document PolicyTestSuite YAML payload.
func ParseTestSuite(raw []byte) (*TestSuite, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, fmt.Errorf("policy test suite must not be empty")
	}

	var suite TestSuite
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&suite); err != nil {
		return nil, fmt.Errorf("parse policy test suite: %w", err)
	}

	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("policy test suite must contain a single YAML document")
	}

	suite.APIVersion = strings.TrimSpace(suite.APIVersion)
	suite.Kind = strings.TrimSpace(suite.Kind)
	suite.Metadata.Name = strings.TrimSpace(suite.Metadata.Name)

	if suite.APIVersion != APIVersionV1 {
		return nil, fmt.Errorf("unsupported test suite apiVersion %q (expected %q)", suite.APIVersion, APIVersionV1)
	}
	if suite.Kind != KindPolicyTestSuite {
		return nil, fmt.Errorf("invalid test suite kind %q (expected %q)", suite.Kind, KindPolicyTestSuite)
	}
	if suite.Metadata.Name == "" {
		return nil, fmt.Errorf("test suite metadata.name must not be empty")
	}
	if len(suite.Cases) == 0 {
		return nil, fmt.Errorf("test suite must define at least one test case")
	}

	for i := range suite.Cases {
		c := &suite.Cases[i]
		c.Name = strings.TrimSpace(c.Name)
		c.Stage = strings.TrimSpace(c.Stage)
		if c.Name == "" {
			return nil, fmt.Errorf("cases[%d].name must not be empty", i)
		}
		if !IsValidStage(c.Stage) {
			return nil, fmt.Errorf("case %q has invalid stage %q", c.Name, c.Stage)
		}
		if !c.Expect.Effect.IsValid() {
			return nil, fmt.Errorf("case %q has invalid expected effect %q", c.Name, c.Expect.Effect)
		}
	}

	return &suite, nil
}

// LoadTestSuite reads and parses a PolicyTestSuite YAML file from disk.
func LoadTestSuite(path string) (*TestSuite, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read test suite %q: %w", path, err)
	}
	return ParseTestSuite(raw)
}

// RunTestSuite executes all cases in suite. If overrideBundle is non-nil and a case
// does not specify its own bundle/org_bundle, overrideBundle is evaluated.
func (e *Engine) RunTestSuite(ctx context.Context, suite *TestSuite, baseDir string, overrideBundle *CompiledBundle) (TestSuiteReport, error) {
	if suite == nil {
		return TestSuiteReport{}, fmt.Errorf("test suite must not be nil")
	}

	cache := make(map[string]*CompiledBundle)
	resolveBundle := func(pathVal, yamlVal string, fallback *CompiledBundle) (*CompiledBundle, error) {
		if strings.TrimSpace(yamlVal) != "" {
			cb, errs := e.Compile([]byte(yamlVal))
			if len(errs) > 0 {
				return nil, fmt.Errorf("compile inline bundle: [%s] %s", errs[0].Code, errs[0].Message)
			}
			return cb, nil
		}
		if strings.TrimSpace(pathVal) != "" {
			resolved := pathVal
			if !filepath.IsAbs(resolved) && baseDir != "" {
				resolved = filepath.Join(baseDir, resolved)
			}
			resolved = filepath.Clean(resolved)
			if cached, ok := cache[resolved]; ok {
				return cached, nil
			}
			cb, err := e.LoadBundleFile(resolved)
			if err != nil {
				return nil, err
			}
			cache[resolved] = cb
			return cb, nil
		}
		return fallback, nil
	}

	defaultBundle, err := resolveBundle(suite.Bundle, suite.BundleYAML, overrideBundle)
	if err != nil {
		return TestSuiteReport{}, fmt.Errorf("suite %q bundle: %w", suite.Metadata.Name, err)
	}
	defaultOrgBundle, err := resolveBundle(suite.OrgBundle, suite.OrgBundleYAML, nil)
	if err != nil {
		return TestSuiteReport{}, fmt.Errorf("suite %q org_bundle: %w", suite.Metadata.Name, err)
	}

	report := TestSuiteReport{
		SuiteName: suite.Metadata.Name,
		Cases:     make([]TestCaseResult, 0, len(suite.Cases)),
	}

	for _, tc := range suite.Cases {
		caseBundle, err := resolveBundle(tc.Bundle, tc.BundleYAML, defaultBundle)
		if err != nil {
			report.Failed++
			report.Cases = append(report.Cases, TestCaseResult{
				Name:          tc.Name,
				Passed:        false,
				FailureReason: fmt.Sprintf("resolve bundle: %v", err),
			})
			continue
		}
		caseOrgBundle, err := resolveBundle(tc.OrgBundle, tc.OrgBundleYAML, defaultOrgBundle)
		if err != nil {
			report.Failed++
			report.Cases = append(report.Cases, TestCaseResult{
				Name:          tc.Name,
				Passed:        false,
				FailureReason: fmt.Sprintf("resolve org bundle: %v", err),
			})
			continue
		}

		if caseOrgBundle == nil && caseBundle == nil {
			report.Failed++
			report.Cases = append(report.Cases, TestCaseResult{
				Name:          tc.Name,
				Passed:        false,
				FailureReason: "no policy bundle or org_bundle specified for test case",
			})
			continue
		}

		var res EvalResult
		if caseOrgBundle != nil && caseBundle != nil {
			res, err = e.ComposeAndEvaluate(ctx, caseOrgBundle, caseBundle, tc.Stage, tc.Input)
		} else if caseOrgBundle != nil {
			res, err = e.Evaluate(ctx, caseOrgBundle, tc.Stage, tc.Input)
		} else {
			res, err = e.Evaluate(ctx, caseBundle, tc.Stage, tc.Input)
		}
		if err != nil {
			report.Failed++
			report.Cases = append(report.Cases, TestCaseResult{
				Name:          tc.Name,
				Passed:        false,
				FailureReason: fmt.Sprintf("evaluate error: %v", err),
			})
			continue
		}

		failure := checkExpectation(res, tc.Expect)
		if failure != "" {
			report.Failed++
			report.Cases = append(report.Cases, TestCaseResult{
				Name:          tc.Name,
				Passed:        false,
				FailureReason: failure,
				ActualEffect:  res.Effect,
				EvalResult:    &res,
			})
			continue
		}

		report.Passed++
		report.Cases = append(report.Cases, TestCaseResult{
			Name:         tc.Name,
			Passed:       true,
			ActualEffect: res.Effect,
			EvalResult:   &res,
		})
	}

	return report, nil
}

// RunTestDir discovers and executes all *.yaml/*.yml PolicyTestSuite files in dir in sorted order.
func (e *Engine) RunTestDir(ctx context.Context, dir string) (TestDirReport, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return TestDirReport{}, fmt.Errorf("read policy test directory %q: %w", dir, err)
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
		return TestDirReport{}, fmt.Errorf("policy test directory %q contains no *.yaml/*.yml test suites", dir)
	}

	dirReport := TestDirReport{
		Dir:    dir,
		Suites: make([]TestSuiteReport, 0, len(files)),
	}

	for _, name := range files {
		fullPath := filepath.Join(dir, name)
		suite, err := LoadTestSuite(fullPath)
		if err != nil {
			return TestDirReport{}, fmt.Errorf("load test suite %q: %w", fullPath, err)
		}
		suiteRep, err := e.RunTestSuite(ctx, suite, dir, nil)
		if err != nil {
			return TestDirReport{}, fmt.Errorf("run test suite %q: %w", fullPath, err)
		}
		suiteRep.FilePath = fullPath
		dirReport.Passed += suiteRep.Passed
		dirReport.Failed += suiteRep.Failed
		dirReport.Suites = append(dirReport.Suites, suiteRep)
	}

	return dirReport, nil
}

func checkExpectation(res EvalResult, exp TestExpectation) string {
	if res.Effect != exp.Effect {
		return fmt.Sprintf("effect mismatch: got %s, want %s (matched=%v)", res.Effect, exp.Effect, res.MatchedRuleIDs)
	}
	for _, wantRule := range exp.MatchedRules {
		if !slices.Contains(res.MatchedRuleIDs, wantRule) {
			return fmt.Sprintf("expected matched rule %q not found in %v", wantRule, res.MatchedRuleIDs)
		}
	}
	for _, absentRule := range exp.AbsentRules {
		if slices.Contains(res.MatchedRuleIDs, absentRule) {
			return fmt.Sprintf("expected rule %q to be absent from matched rules %v", absentRule, res.MatchedRuleIDs)
		}
	}
	for _, wantObl := range exp.Obligations {
		wantType := strings.TrimSpace(wantObl.Type)
		if wantType == "" {
			wantType = DefaultObligationType
		}
		wantMin := 1
		if wantObl.Minimum != nil && *wantObl.Minimum >= 1 {
			wantMin = *wantObl.Minimum
		}
		found := false
		for _, gotObl := range res.Obligations {
			if gotObl.Type == wantType && gotObl.ReviewerGroup == wantObl.ReviewerGroup && gotObl.Minimum >= wantMin {
				found = true
				break
			}
		}
		if !found {
			return fmt.Sprintf("expected obligation {type:%q reviewer_group:%q minimum:%d} not found in %+v", wantType, wantObl.ReviewerGroup, wantMin, res.Obligations)
		}
	}
	if exp.ExpectTraceError {
		hasTraceErr := false
		for _, rt := range res.RuleTrace {
			if strings.TrimSpace(rt.Error) != "" {
				hasTraceErr = true
				break
			}
		}
		if !hasTraceErr {
			return fmt.Sprintf("expected CEL runtime error in rule_trace, got %+v", res.RuleTrace)
		}
	}
	return ""
}
