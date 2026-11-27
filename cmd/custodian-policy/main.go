package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/timreynolds/custodian/internal/policy"
)

const usageText = `custodian-policy - Custodian CEL policy validation, simulation, and test CLI

Usage:
  custodian-policy <command> [flags]

Commands:
  validate   Validate and compile a YAML PolicyBundle (and optional PolicyTestSuite)
  evaluate   Evaluate a PolicyBundle (or composed ORG+REPO bundles) against a JSON input
  test       Execute all PolicyTestSuite YAML files in a directory
  help       Show this help message

Run "custodian-policy <command> --help" for command-specific flags.
`

const validateUsageText = `Usage:
  custodian-policy validate --bundle <path> [--tests <path>] [--format text|json]
`

const evaluateUsageText = `Usage:
  custodian-policy evaluate --bundle <path> [--org-bundle <path>] --input <path> [--stage INGRESS|EGRESS|PUSH_EGRESS] [--format json|text]
`

const testUsageText = `Usage:
  custodian-policy test [--format text|json] <dir>
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}

	if len(args) == 0 {
		_, _ = io.WriteString(stdout, usageText)
		return 0
	}

	switch args[0] {
	case "--help", "-h", "help":
		_, _ = io.WriteString(stdout, usageText)
		return 0
	case "validate":
		return runValidate(ctx, args[1:], stdout, stderr)
	case "evaluate":
		return runEvaluate(ctx, args[1:], stdout, stderr)
	case "test":
		return runTest(ctx, args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usageText)
		return 2
	}
}

func runValidate(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var bundlePath, testsPath, format string
	var help bool
	fs.StringVar(&bundlePath, "bundle", "", "path to PolicyBundle YAML file")
	fs.StringVar(&testsPath, "tests", "", "optional path to PolicyTestSuite YAML file")
	fs.StringVar(&format, "format", "text", "output format (text|json)")
	fs.BoolVar(&help, "help", false, "show help")
	fs.BoolVar(&help, "h", false, "show help")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.WriteString(stdout, validateUsageText)
			return 0
		}
		_, _ = fmt.Fprintf(stderr, "error: %v\n%s", err, validateUsageText)
		return 2
	}
	if help {
		_, _ = io.WriteString(stdout, validateUsageText)
		return 0
	}
	if strings.TrimSpace(bundlePath) == "" {
		_, _ = fmt.Fprintf(stderr, "error: --bundle is required\n%s", validateUsageText)
		return 2
	}

	bundleBytes, err := os.ReadFile(bundlePath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error reading bundle %q: %v\n", bundlePath, err)
		return 1
	}

	var testBytes []byte
	if strings.TrimSpace(testsPath) != "" {
		testBytes, err = os.ReadFile(testsPath)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error reading test suite %q: %v\n", testsPath, err)
			return 1
		}
	}

	engine, err := policy.NewEngine()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error initializing policy engine: %v\n", err)
		return 1
	}

	var res policy.ValidationResult
	var report *policy.TestSuiteReport
	if len(testBytes) > 0 {
		res, report = engine.ValidateWithTests(ctx, bundleBytes, testBytes)
	} else {
		res = engine.Validate(bundleBytes)
	}

	passed := res.Valid && (report == nil || report.AllPassed())

	switch strings.ToLower(strings.TrimSpace(format)) {
	case "json":
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(struct {
			policy.ValidationResult
			TestReport *policy.TestSuiteReport `json:"test_report,omitempty"`
		}{
			ValidationResult: res,
			TestReport:       report,
		})
	default:
		status := "VALID"
		if !passed {
			status = "INVALID"
		}
		_, _ = fmt.Fprintf(stdout, "%s bundle=%s version=%s digest=%s rules_compiled=%d\n",
			status, res.Name, res.Version, res.Digest, res.RulesCompiled)
		for _, e := range res.Errors {
			if e.RuleID != "" {
				_, _ = fmt.Fprintf(stderr, "  [%s] rule=%s: %s\n", e.Code, e.RuleID, e.Message)
			} else {
				_, _ = fmt.Fprintf(stderr, "  [%s]: %s\n", e.Code, e.Message)
			}
		}
		if report != nil {
			_, _ = fmt.Fprintf(stdout, "TESTS %s: %d passed, %d failed\n", report.SuiteName, report.Passed, report.Failed)
		}
	}

	if !passed {
		return 1
	}
	return 0
}

func runEvaluate(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("evaluate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var bundlePath, orgBundlePath, inputPath, stage, format string
	var help bool
	fs.StringVar(&bundlePath, "bundle", "", "path to PolicyBundle YAML file")
	fs.StringVar(&orgBundlePath, "org-bundle", "", "optional path to ORG PolicyBundle YAML file")
	fs.StringVar(&inputPath, "input", "", "path to JSON input file")
	fs.StringVar(&stage, "stage", "", "policy stage (INGRESS|EGRESS|PUSH_EGRESS)")
	fs.StringVar(&format, "format", "json", "output format (json|text)")
	fs.BoolVar(&help, "help", false, "show help")
	fs.BoolVar(&help, "h", false, "show help")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.WriteString(stdout, evaluateUsageText)
			return 0
		}
		_, _ = fmt.Fprintf(stderr, "error: %v\n%s", err, evaluateUsageText)
		return 2
	}
	if help {
		_, _ = io.WriteString(stdout, evaluateUsageText)
		return 0
	}
	if strings.TrimSpace(bundlePath) == "" || strings.TrimSpace(inputPath) == "" {
		_, _ = fmt.Fprintf(stderr, "error: --bundle and --input are required\n%s", evaluateUsageText)
		return 2
	}

	engine, err := policy.NewEngine()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error initializing policy engine: %v\n", err)
		return 1
	}

	compiled, err := engine.LoadBundleFile(bundlePath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error loading bundle: %v\n", err)
		return 1
	}

	var orgCompiled *policy.CompiledBundle
	if strings.TrimSpace(orgBundlePath) != "" {
		orgCompiled, err = engine.LoadBundleFile(orgBundlePath)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error loading org bundle: %v\n", err)
			return 1
		}
	}

	rawInput, err := os.ReadFile(inputPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error reading input %q: %v\n", inputPath, err)
		return 1
	}

	resolvedStage := strings.ToUpper(strings.TrimSpace(stage))
	if resolvedStage == "" {
		var peek struct {
			Stage string `json:"stage"`
		}
		if err := json.Unmarshal(rawInput, &peek); err == nil && strings.TrimSpace(peek.Stage) != "" {
			resolvedStage = strings.ToUpper(strings.TrimSpace(peek.Stage))
		} else {
			resolvedStage = policy.StageEgress
		}
	}
	if !policy.IsValidStage(resolvedStage) {
		_, _ = fmt.Fprintf(stderr, "error: invalid stage %q (must be INGRESS, EGRESS, or PUSH_EGRESS)\n", resolvedStage)
		return 2
	}

	var evalRes policy.EvalResult
	if orgCompiled != nil {
		evalRes, err = engine.ComposeAndEvaluate(ctx, orgCompiled, compiled, resolvedStage, rawInput)
	} else {
		evalRes, err = engine.Evaluate(ctx, compiled, resolvedStage, rawInput)
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error evaluating policy: %v\n", err)
		return 1
	}

	switch strings.ToLower(strings.TrimSpace(format)) {
	case "text":
		_, _ = fmt.Fprintf(stdout, "EFFECT: %s\nBUNDLE_DIGEST: %s\nINPUT_DIGEST: %s\nMATCHED_RULES: %s\n",
			evalRes.Effect, evalRes.BundleDigest, evalRes.InputDigest, strings.Join(evalRes.MatchedRuleIDs, ","))
		for _, obl := range evalRes.Obligations {
			_, _ = fmt.Fprintf(stdout, "OBLIGATION: type=%s reviewer_group=%s minimum=%d\n", obl.Type, obl.ReviewerGroup, obl.Minimum)
		}
	default:
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(evalRes)
	}
	return 0
}

func runTest(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var format string
	var help bool
	fs.StringVar(&format, "format", "text", "output format (text|json)")
	fs.BoolVar(&help, "help", false, "show help")
	fs.BoolVar(&help, "h", false, "show help")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.WriteString(stdout, testUsageText)
			return 0
		}
		_, _ = fmt.Fprintf(stderr, "error: %v\n%s", err, testUsageText)
		return 2
	}
	if help {
		_, _ = io.WriteString(stdout, testUsageText)
		return 0
	}
	if fs.NArg() < 1 {
		_, _ = fmt.Fprintf(stderr, "error: test directory argument is required\n%s", testUsageText)
		return 2
	}
	dir := fs.Arg(0)

	engine, err := policy.NewEngine()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error initializing policy engine: %v\n", err)
		return 1
	}

	report, err := engine.RunTestDir(ctx, dir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error running policy tests: %v\n", err)
		return 1
	}

	switch strings.ToLower(strings.TrimSpace(format)) {
	case "json":
		b, mErr := report.FormatJSON()
		if mErr != nil {
			_, _ = fmt.Fprintf(stderr, "error formatting JSON report: %v\n", mErr)
			return 1
		}
		_, _ = stdout.Write(append(b, '\n'))
	default:
		_, _ = io.WriteString(stdout, report.FormatText())
	}

	if !report.AllPassed() {
		return 1
	}
	return 0
}
