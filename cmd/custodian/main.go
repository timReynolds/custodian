package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/timreynolds/custodian/internal/domain"
)

const defaultAPIURL = "http://127.0.0.1:8080"

const usageText = `custodian - Custodian policy-governed Git broker CLI

Usage:
  custodian [--api-url <url>] [--token <jwt>] <command> <subcommand> [flags]

Environment Variables:
  CUSTODIAN_API_URL   Base URL for custodian-api (default: http://127.0.0.1:8080)
  CUSTODIAN_TOKEN     Bearer OIDC JWT for authenticated /v1 requests

Commands:
  health                        Check API liveness (/healthz)
  ready                         Check API readiness (/readyz)
  workspaces create|get|source  Manage workspaces
  proposals submit|get|diff|findings|assessments|evaluate|approve|publish
                                Manage change proposals
  publications get <id>         Inspect publication status
  operations get <id>           Poll operation status
  audit list                    Query hash-chained audit events
  policies validate|evaluate    Validate or simulate CEL policies via API
  help                          Show this help message
`

type cliClient struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	if getenv == nil {
		getenv = os.Getenv
	}

	globalFS := flag.NewFlagSet("custodian", flag.ContinueOnError)
	globalFS.SetOutput(io.Discard)
	apiURL := strings.TrimSpace(getenv("CUSTODIAN_API_URL"))
	if apiURL == "" {
		apiURL = defaultAPIURL
	}
	token := strings.TrimSpace(getenv("CUSTODIAN_TOKEN"))
	var help bool
	globalFS.StringVar(&apiURL, "api-url", apiURL, "Custodian API base URL")
	globalFS.StringVar(&token, "token", token, "Bearer token")
	globalFS.BoolVar(&help, "help", false, "show usage")
	globalFS.BoolVar(&help, "h", false, "show usage")

	if err := globalFS.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.WriteString(stdout, usageText)
			return 0
		}
		_, _ = fmt.Fprintf(stderr, "error: %v\n%s", err, usageText)
		return 2
	}
	if help || globalFS.NArg() == 0 {
		_, _ = io.WriteString(stdout, usageText)
		return 0
	}

	rest := globalFS.Args()
	client := &cliClient{
		baseURL:    strings.TrimRight(apiURL, "/"),
		token:      token,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}

	switch rest[0] {
	case "help", "--help", "-h":
		_, _ = io.WriteString(stdout, usageText)
		return 0
	case "health":
		return client.doAndPrint(ctx, http.MethodGet, "/healthz", nil, "", false, stdout, stderr)
	case "ready":
		return client.doAndPrint(ctx, http.MethodGet, "/readyz", nil, "", false, stdout, stderr)
	case "workspaces":
		return runWorkspaces(ctx, client, rest[1:], stdout, stderr)
	case "proposals":
		return runProposals(ctx, client, rest[1:], stdout, stderr)
	case "publications":
		return runGetResourceCmd(ctx, client, "publications", "/v1/publications/", rest[1:], stdout, stderr)
	case "operations":
		return runGetResourceCmd(ctx, client, "operations", "/v1/operations/", rest[1:], stdout, stderr)
	case "audit":
		return runAudit(ctx, client, rest[1:], stdout, stderr)
	case "policies":
		return runPolicies(ctx, client, rest[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command %q\n\n%s", rest[0], usageText)
		return 2
	}
}

func runWorkspaces(ctx context.Context, client *cliClient, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		_, _ = io.WriteString(stdout, "Usage: custodian workspaces <create|get|source> ...\n")
		return 0
	}
	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("workspaces create", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		var repoID int64
		var ref, agentType, agentSession, modelRoute, idemKey string
		var includeGitMeta, includeHistory, help bool
		fs.Int64Var(&repoID, "repo-id", 0, "GitHub repository ID")
		fs.StringVar(&ref, "ref", "", "Git ref or commit SHA")
		fs.StringVar(&agentType, "agent-type", "", "Agent type")
		fs.StringVar(&agentSession, "agent-session", "", "Agent session ID")
		fs.StringVar(&modelRoute, "model-route", "", "Model route")
		fs.BoolVar(&includeGitMeta, "include-git-metadata", false, "Include sanitized .git metadata")
		fs.BoolVar(&includeHistory, "include-history", false, "Include full git history")
		fs.StringVar(&idemKey, "idempotency-key", "", "Idempotency-Key header")
		fs.BoolVar(&help, "help", false, "show help")
		fs.BoolVar(&help, "h", false, "show help")
		if err := fs.Parse(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				_, _ = io.WriteString(stdout, "Usage: custodian workspaces create --repo-id <id> --ref <ref> [--agent-type ... --agent-session ... --model-route ...]\n")
				return 0
			}
			_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
		if help {
			_, _ = io.WriteString(stdout, "Usage: custodian workspaces create --repo-id <id> --ref <ref> [--agent-type ... --agent-session ... --model-route ...]\n")
			return 0
		}
		if repoID < 1 || strings.TrimSpace(ref) == "" {
			_, _ = fmt.Fprintln(stderr, "error: --repo-id and --ref are required")
			return 2
		}
		hasAnyAgent := agentType != "" || agentSession != "" || modelRoute != ""
		if hasAnyAgent && (strings.TrimSpace(agentType) == "" || strings.TrimSpace(agentSession) == "" || strings.TrimSpace(modelRoute) == "") {
			_, _ = fmt.Fprintln(stderr, "error: --agent-type, --agent-session, and --model-route must all be non-empty when agent flags are provided")
			return 2
		}
		payload := map[string]any{
			"repository": map[string]any{
				"provider":      "github",
				"repository_id": repoID,
				"ref":           ref,
			},
			"source_options": map[string]any{
				"include_git_metadata": includeGitMeta,
				"include_history":      includeHistory,
			},
		}
		if hasAnyAgent {
			payload["agent"] = map[string]any{
				"type":        strings.TrimSpace(agentType),
				"session_id":  strings.TrimSpace(agentSession),
				"model_route": strings.TrimSpace(modelRoute),
			}
		}
		return client.doAndPrint(ctx, http.MethodPost, "/v1/workspaces", payload, idemKey, true, stdout, stderr)
	case "get":
		if hasHelpArg(args[1:]) {
			_, _ = io.WriteString(stdout, "Usage: custodian workspaces get <id>\n")
			return 0
		}
		if len(args) < 2 {
			_, _ = fmt.Fprintln(stderr, "Usage: custodian workspaces get <id>")
			return 2
		}
		return client.doAndPrint(ctx, http.MethodGet, "/v1/workspaces/"+url.PathEscape(args[1]), nil, "", false, stdout, stderr)
	case "source":
		if hasHelpArg(args[1:]) {
			_, _ = io.WriteString(stdout, "Usage: custodian workspaces source <id>\n")
			return 0
		}
		if len(args) < 2 {
			_, _ = fmt.Fprintln(stderr, "Usage: custodian workspaces source <id>")
			return 2
		}
		return client.doAndPrint(ctx, http.MethodGet, "/v1/workspaces/"+url.PathEscape(args[1])+"/source", nil, "", false, stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "unknown workspaces subcommand %q\n", args[0])
		return 2
	}
}

func isHelpArg(arg string) bool {
	return arg == "--help" || arg == "-h" || arg == "help"
}

func hasHelpArg(args []string) bool {
	for _, a := range args {
		if isHelpArg(a) {
			return true
		}
	}
	return false
}

func runProposals(ctx context.Context, client *cliClient, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || isHelpArg(args[0]) {
		_, _ = io.WriteString(stdout, "Usage: custodian proposals <submit|get|diff|findings|assessments|evaluate|approve|publish> ...\n")
		return 0
	}
	sub := args[0]
	switch sub {
	case "get":
		if hasHelpArg(args[1:]) {
			_, _ = io.WriteString(stdout, "Usage: custodian proposals get <id>\n")
			return 0
		}
		if len(args) < 2 {
			_, _ = fmt.Fprintln(stderr, "Usage: custodian proposals get <id>")
			return 2
		}
		return client.doAndPrint(ctx, http.MethodGet, "/v1/proposals/"+url.PathEscape(args[1]), nil, "", false, stdout, stderr)
	case "diff":
		if hasHelpArg(args[1:]) {
			_, _ = io.WriteString(stdout, "Usage: custodian proposals diff <id>\n")
			return 0
		}
		if len(args) < 2 {
			_, _ = fmt.Fprintln(stderr, "Usage: custodian proposals diff <id>")
			return 2
		}
		return client.doAndPrint(ctx, http.MethodGet, "/v1/proposals/"+url.PathEscape(args[1])+"/diff", nil, "", false, stdout, stderr)
	case "assessments":
		if hasHelpArg(args[1:]) {
			_, _ = io.WriteString(stdout, "Usage: custodian proposals assessments <id>\n")
			return 0
		}
		if len(args) < 2 {
			_, _ = fmt.Fprintln(stderr, "Usage: custodian proposals assessments <id>")
			return 2
		}
		return client.doAndPrint(ctx, http.MethodGet, "/v1/proposals/"+url.PathEscape(args[1])+"/assessments", nil, "", false, stdout, stderr)
	case "findings":
		const findingsUsage = "Usage: custodian proposals findings <id> [--scanner ...] [--severity ...] [--limit ...]\n"
		if len(args) >= 2 && isHelpArg(args[1]) {
			_, _ = io.WriteString(stdout, findingsUsage)
			return 0
		}
		if len(args) < 2 {
			_, _ = io.WriteString(stderr, findingsUsage)
			return 2
		}
		propID := args[1]
		fs := flag.NewFlagSet("proposals findings", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		var scanner, severity, cursor string
		var limit int
		var help bool
		fs.StringVar(&scanner, "scanner", "", "scanner filter")
		fs.StringVar(&severity, "severity", "", "severity filter")
		fs.StringVar(&cursor, "cursor", "", "pagination cursor")
		fs.IntVar(&limit, "limit", 0, "limit")
		fs.BoolVar(&help, "help", false, "show help")
		fs.BoolVar(&help, "h", false, "show help")
		if err := fs.Parse(args[2:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				_, _ = io.WriteString(stdout, findingsUsage)
				return 0
			}
			_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
		if help {
			_, _ = io.WriteString(stdout, findingsUsage)
			return 0
		}
		q := url.Values{}
		if scanner != "" {
			q.Set("scanner", scanner)
		}
		if severity != "" {
			q.Set("severity", severity)
		}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		if limit > 0 {
			q.Set("limit", fmt.Sprintf("%d", limit))
		}
		p := "/v1/proposals/" + url.PathEscape(propID) + "/findings"
		if enc := q.Encode(); enc != "" {
			p += "?" + enc
		}
		return client.doAndPrint(ctx, http.MethodGet, p, nil, "", false, stdout, stderr)
	case "evaluate":
		const evalUsage = "Usage: custodian proposals evaluate <id> [--expected-version <n>]\n"
		if len(args) >= 2 && isHelpArg(args[1]) {
			_, _ = io.WriteString(stdout, evalUsage)
			return 0
		}
		if len(args) < 2 {
			_, _ = io.WriteString(stderr, evalUsage)
			return 2
		}
		propID := args[1]
		fs := flag.NewFlagSet("proposals evaluate", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		var expectedVer int64
		var idemKey string
		var help bool
		fs.Int64Var(&expectedVer, "expected-version", 0, "optimistic proposal version")
		fs.StringVar(&idemKey, "idempotency-key", "", "Idempotency-Key")
		fs.BoolVar(&help, "help", false, "show help")
		fs.BoolVar(&help, "h", false, "show help")
		if err := fs.Parse(args[2:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				_, _ = io.WriteString(stdout, evalUsage)
				return 0
			}
			_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
		if help {
			_, _ = io.WriteString(stdout, evalUsage)
			return 0
		}
		var payload any
		if expectedVer > 0 {
			payload = map[string]any{"expected_version": expectedVer}
		} else {
			payload = map[string]any{}
		}
		return client.doAndPrint(ctx, http.MethodPost, "/v1/proposals/"+url.PathEscape(propID)+"/evaluate", payload, idemKey, true, stdout, stderr)
	case "approve":
		const approveUsage = "Usage: custodian proposals approve <id> --decision APPROVE|REJECT --manifest-digest <sha256> --policy-evaluation-id <uuid>\n"
		if len(args) >= 2 && isHelpArg(args[1]) {
			_, _ = io.WriteString(stdout, approveUsage)
			return 0
		}
		if len(args) < 2 {
			_, _ = io.WriteString(stderr, approveUsage)
			return 2
		}
		propID := args[1]
		fs := flag.NewFlagSet("proposals approve", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		var decision, digest, evalID, comment, idemKey string
		var help bool
		fs.StringVar(&decision, "decision", "APPROVE", "APPROVE or REJECT")
		fs.StringVar(&digest, "manifest-digest", "", "publication_manifest_digest")
		fs.StringVar(&evalID, "policy-evaluation-id", "", "policy_evaluation_id")
		fs.StringVar(&comment, "comment", "", "optional comment")
		fs.StringVar(&idemKey, "idempotency-key", "", "Idempotency-Key")
		fs.BoolVar(&help, "help", false, "show help")
		fs.BoolVar(&help, "h", false, "show help")
		if err := fs.Parse(args[2:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				_, _ = io.WriteString(stdout, approveUsage)
				return 0
			}
			_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
		if help {
			_, _ = io.WriteString(stdout, approveUsage)
			return 0
		}
		if digest == "" || evalID == "" {
			_, _ = fmt.Fprintln(stderr, "error: --manifest-digest and --policy-evaluation-id are required")
			return 2
		}
		payload := map[string]any{
			"decision":                    decision,
			"publication_manifest_digest": digest,
			"policy_evaluation_id":        evalID,
		}
		if comment != "" {
			payload["comment"] = comment
		}
		return client.doAndPrint(ctx, http.MethodPost, "/v1/proposals/"+url.PathEscape(propID)+"/approvals", payload, idemKey, true, stdout, stderr)
	case "publish":
		const publishUsage = "Usage: custodian proposals publish <id> --manifest-digest <sha256>\n"
		if len(args) >= 2 && isHelpArg(args[1]) {
			_, _ = io.WriteString(stdout, publishUsage)
			return 0
		}
		if len(args) < 2 {
			_, _ = io.WriteString(stderr, publishUsage)
			return 2
		}
		propID := args[1]
		fs := flag.NewFlagSet("proposals publish", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		var digest, idemKey string
		var help bool
		fs.StringVar(&digest, "manifest-digest", "", "publication_manifest_digest")
		fs.StringVar(&idemKey, "idempotency-key", "", "Idempotency-Key")
		fs.BoolVar(&help, "help", false, "show help")
		fs.BoolVar(&help, "h", false, "show help")
		if err := fs.Parse(args[2:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				_, _ = io.WriteString(stdout, publishUsage)
				return 0
			}
			_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
		if help {
			_, _ = io.WriteString(stdout, publishUsage)
			return 0
		}
		if digest == "" {
			_, _ = fmt.Fprintln(stderr, "error: --manifest-digest is required")
			return 2
		}
		return client.doAndPrint(ctx, http.MethodPost, "/v1/proposals/"+url.PathEscape(propID)+"/publish", map[string]any{
			"publication_manifest_digest": digest,
		}, idemKey, true, stdout, stderr)
	case "submit":
		const submitUsage = "Usage: custodian proposals submit <workspace-id> --artifact-id <uuid> --sha256 <hex> --generation <n> --title <title>\n"
		if len(args) >= 2 && isHelpArg(args[1]) {
			_, _ = io.WriteString(stdout, submitUsage)
			return 0
		}
		if len(args) < 2 {
			_, _ = io.WriteString(stderr, submitUsage)
			return 2
		}
		wsID := args[1]
		fs := flag.NewFlagSet("proposals submit", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		var artID, sha, title, desc, provType, capMethod, idemKey string
		var gen, sizeBytes int64
		var help bool
		fs.StringVar(&artID, "artifact-id", "", "snapshot artifact ID")
		fs.StringVar(&sha, "sha256", "", "snapshot sha256")
		fs.Int64Var(&gen, "generation", 1, "workspace generation")
		fs.Int64Var(&sizeBytes, "size-bytes", 0, "snapshot size bytes")
		fs.StringVar(&title, "title", "", "proposal title")
		fs.StringVar(&desc, "description", "", "proposal description")
		fs.StringVar(&provType, "provenance-type", "agent_assisted", "agent_assisted|human_authored")
		fs.StringVar(&capMethod, "capture-method", "frozen_filesystem", "frozen_filesystem|patch_upload")
		fs.StringVar(&idemKey, "idempotency-key", "", "Idempotency-Key")
		fs.BoolVar(&help, "help", false, "show help")
		fs.BoolVar(&help, "h", false, "show help")
		if err := fs.Parse(args[2:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				_, _ = io.WriteString(stdout, submitUsage)
				return 0
			}
			_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
		if help {
			_, _ = io.WriteString(stdout, submitUsage)
			return 0
		}
		if artID == "" || sha == "" || title == "" {
			_, _ = fmt.Fprintln(stderr, "error: --artifact-id, --sha256, and --title are required")
			return 2
		}
		snap := map[string]any{
			"artifact_id":          artID,
			"sha256":               sha,
			"workspace_generation": gen,
		}
		if sizeBytes > 0 {
			snap["size_bytes"] = sizeBytes
		}
		payload := map[string]any{
			"snapshot": snap,
			"title":    title,
			"provenance": map[string]any{
				"type":           provType,
				"capture_method": capMethod,
			},
		}
		if desc != "" {
			payload["description"] = desc
		}
		return client.doAndPrint(ctx, http.MethodPost, "/v1/workspaces/"+url.PathEscape(wsID)+"/proposals", payload, idemKey, true, stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "unknown proposals subcommand %q\n", sub)
		return 2
	}
}

func runGetResourceCmd(ctx context.Context, client *cliClient, name, prefix string, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || isHelpArg(args[0]) {
		_, _ = fmt.Fprintf(stdout, "Usage: custodian %s get <id>\n", name)
		return 0
	}
	if args[0] == "get" && hasHelpArg(args[1:]) {
		_, _ = fmt.Fprintf(stdout, "Usage: custodian %s get <id>\n", name)
		return 0
	}
	if args[0] != "get" || len(args) < 2 {
		_, _ = fmt.Fprintf(stderr, "Usage: custodian %s get <id>\n", name)
		return 2
	}
	return client.doAndPrint(ctx, http.MethodGet, prefix+url.PathEscape(args[1]), nil, "", false, stdout, stderr)
}

func runAudit(ctx context.Context, client *cliClient, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		_, _ = io.WriteString(stdout, "Usage: custodian audit list [--resource-type ...] [--resource-id ...] [--event-type ...] [--actor-id ...] [--since ...] [--until ...] [--cursor ...] [--limit ...]\n")
		return 0
	}
	if args[0] != "list" {
		_, _ = fmt.Fprintf(stderr, "unknown audit subcommand %q\n", args[0])
		return 2
	}
	fs := flag.NewFlagSet("audit list", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var resType, resID, evType, actorID, since, until, cursor string
	var limit int
	fs.StringVar(&resType, "resource-type", "", "resource_type filter")
	fs.StringVar(&resID, "resource-id", "", "resource_id filter")
	fs.StringVar(&evType, "event-type", "", "event_type filter")
	fs.StringVar(&actorID, "actor-id", "", "actor_id filter")
	fs.StringVar(&since, "since", "", "RFC3339 start timestamp")
	fs.StringVar(&until, "until", "", "RFC3339 end timestamp")
	fs.StringVar(&cursor, "cursor", "", "pagination cursor")
	fs.IntVar(&limit, "limit", 0, "limit")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.WriteString(stdout, "Usage: custodian audit list [flags]\n")
			return 0
		}
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	q := url.Values{}
	if resType != "" {
		q.Set("resource_type", resType)
	}
	if resID != "" {
		q.Set("resource_id", resID)
	}
	if evType != "" {
		q.Set("event_type", evType)
	}
	if actorID != "" {
		q.Set("actor_id", actorID)
	}
	if since != "" {
		q.Set("since", since)
	}
	if until != "" {
		q.Set("until", until)
	}
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	if limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", limit))
	}
	p := "/v1/audit/events"
	if enc := q.Encode(); enc != "" {
		p += "?" + enc
	}
	return client.doAndPrint(ctx, http.MethodGet, p, nil, "", false, stdout, stderr)
}

func runPolicies(ctx context.Context, client *cliClient, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || isHelpArg(args[0]) {
		_, _ = io.WriteString(stdout, "Usage: custodian policies <validate|evaluate> ...\n")
		return 0
	}
	switch args[0] {
	case "validate":
		const validateUsage = "Usage: custodian policies validate --bundle <path> [--tests <path>]\n"
		fs := flag.NewFlagSet("policies validate", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		var bundlePath, testsPath string
		var help bool
		fs.StringVar(&bundlePath, "bundle", "", "path to PolicyBundle YAML")
		fs.StringVar(&testsPath, "tests", "", "optional path to PolicyTestSuite YAML")
		fs.BoolVar(&help, "help", false, "show help")
		fs.BoolVar(&help, "h", false, "show help")
		if err := fs.Parse(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				_, _ = io.WriteString(stdout, validateUsage)
				return 0
			}
			_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
		if help {
			_, _ = io.WriteString(stdout, validateUsage)
			return 0
		}
		if bundlePath == "" {
			_, _ = fmt.Fprintln(stderr, "error: --bundle is required")
			return 2
		}
		b, err := os.ReadFile(bundlePath)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error reading bundle: %v\n", err)
			return 1
		}
		payload := map[string]any{"bundle_yaml": string(b)}
		if testsPath != "" {
			tb, err := os.ReadFile(testsPath)
			if err != nil {
				_, _ = fmt.Fprintf(stderr, "error reading tests: %v\n", err)
				return 1
			}
			payload["test_cases_yaml"] = string(tb)
		}
		return client.doAndPrint(ctx, http.MethodPost, "/v1/policies/validate", payload, "", false, stdout, stderr)
	case "evaluate":
		const evaluateUsage = "Usage: custodian policies evaluate --input <path> [--bundle <path>] [--org-bundle <path>] [--bundle-id <uuid>] [--stage INGRESS|EGRESS]\n"
		fs := flag.NewFlagSet("policies evaluate", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		var bundlePath, orgPath, bundleID, inputPath, stage string
		var help bool
		fs.StringVar(&bundlePath, "bundle", "", "path to PolicyBundle YAML")
		fs.StringVar(&orgPath, "org-bundle", "", "path to ORG PolicyBundle YAML")
		fs.StringVar(&bundleID, "bundle-id", "", "persisted bundle UUIDv7")
		fs.StringVar(&inputPath, "input", "", "path to JSON simulation input")
		fs.StringVar(&stage, "stage", "EGRESS", "INGRESS or EGRESS")
		fs.BoolVar(&help, "help", false, "show help")
		fs.BoolVar(&help, "h", false, "show help")
		if err := fs.Parse(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				_, _ = io.WriteString(stdout, evaluateUsage)
				return 0
			}
			_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
		if help {
			_, _ = io.WriteString(stdout, evaluateUsage)
			return 0
		}
		if inputPath == "" {
			_, _ = fmt.Fprintln(stderr, "error: --input is required")
			return 2
		}
		inBytes, err := os.ReadFile(inputPath)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error reading input: %v\n", err)
			return 1
		}
		var inputMap map[string]any
		if err := json.Unmarshal(inBytes, &inputMap); err != nil {
			_, _ = fmt.Fprintf(stderr, "error parsing input JSON: %v\n", err)
			return 1
		}
		payload := map[string]any{
			"stage": stage,
			"input": inputMap,
		}
		if bundlePath != "" {
			b, err := os.ReadFile(bundlePath)
			if err != nil {
				_, _ = fmt.Fprintf(stderr, "error reading bundle: %v\n", err)
				return 1
			}
			payload["bundle_yaml"] = string(b)
		}
		if orgPath != "" {
			b, err := os.ReadFile(orgPath)
			if err != nil {
				_, _ = fmt.Fprintf(stderr, "error reading org bundle: %v\n", err)
				return 1
			}
			payload["org_bundle_yaml"] = string(b)
		}
		if bundleID != "" {
			payload["bundle_id"] = bundleID
		}
		return client.doAndPrint(ctx, http.MethodPost, "/v1/policies/evaluate", payload, "", false, stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "unknown policies subcommand %q\n", args[0])
		return 2
	}
}

func (c *cliClient) doAndPrint(ctx context.Context, method, path string, body any, idemKey string, requireIdem bool, stdout, stderr io.Writer) int {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error encoding request: %v\n", err)
			return 1
		}
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error building request: %v\n", err)
		return 1
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if requireIdem {
		key := strings.TrimSpace(idemKey)
		if key == "" {
			id, idErr := domain.NewID()
			if idErr != nil {
				_, _ = fmt.Fprintf(stderr, "error generating idempotency key: %v\n", idErr)
				return 1
			}
			key = id.String()
		}
		req.Header.Set("Idempotency-Key", key)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "request failed: %v\n", err)
		return 1
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error reading response: %v\n", err)
		return 1
	}

	if resp.StatusCode >= 400 {
		_, _ = fmt.Fprintf(stderr, "HTTP %d: %s\n", resp.StatusCode, strings.TrimSpace(string(respBytes)))
		return 1
	}

	var pretty bytes.Buffer
	if json.Indent(&pretty, respBytes, "", "  ") == nil {
		_, _ = stdout.Write(append(pretty.Bytes(), '\n'))
	} else {
		_, _ = stdout.Write(respBytes)
		if len(respBytes) > 0 && respBytes[len(respBytes)-1] != '\n' {
			_, _ = io.WriteString(stdout, "\n")
		}
	}
	return 0
}
