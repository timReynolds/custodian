package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/timreynolds/custodian/internal/domain"
)

const defaultAPIURL = "http://127.0.0.1:8080"

const usageText = `custodian - Custodian policy-governed Git broker CLI

Usage:
  custodian [--api-url <url>] [--token <jwt>] [--token-file <path>] <command> <subcommand> [flags]

Environment Variables:
  CUSTODIAN_API_URL        Base URL for custodian-api (default: http://127.0.0.1:8080)
  CUSTODIAN_TOKEN          Bearer OIDC JWT for authenticated /v1 requests
  CUSTODIAN_TOKEN_FILE     Path to file containing Bearer OIDC JWT
  CUSTODIAN_ALLOWED_HOSTS  Optional comma-separated host allowlist for credential-helper

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
  push status [<id>]            Inspect push gateway session status
  credential-helper <op>        Git credential helper (get|store|erase)
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
	return runWithIO(ctx, args, getenv, os.Stdin, stdout, stderr)
}

func runWithIO(ctx context.Context, args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	if stdin == nil {
		stdin = strings.NewReader("")
	}
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
	envAPIURL := strings.TrimSpace(getenv("CUSTODIAN_API_URL"))
	apiURLExplicit := envAPIURL != ""
	apiURL := envAPIURL
	if apiURL == "" {
		apiURL = defaultAPIURL
	}
	token := strings.TrimSpace(getenv("CUSTODIAN_TOKEN"))
	tokenFile := strings.TrimSpace(getenv("CUSTODIAN_TOKEN_FILE"))
	var help, globalTokenExplicit, globalTokenFileExplicit bool
	globalFS.StringVar(&apiURL, "api-url", apiURL, "Custodian API base URL")
	globalFS.StringVar(&token, "token", token, "Bearer token")
	globalFS.StringVar(&tokenFile, "token-file", tokenFile, "Path to Bearer token file")
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
	globalFS.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "api-url":
			apiURLExplicit = true
		case "token":
			globalTokenExplicit = true
		case "token-file":
			globalTokenFileExplicit = true
		}
	})
	if help || globalFS.NArg() == 0 {
		_, _ = io.WriteString(stdout, usageText)
		return 0
	}

	rest := globalFS.Args()
	var resolvedToken string
	if rest[0] != "credential-helper" && rest[0] != "push" {
		var err error
		resolvedToken, err = resolveCLIToken(
			token, globalTokenExplicit,
			tokenFile, globalTokenFileExplicit,
			token, globalTokenExplicit,
			tokenFile, globalTokenFileExplicit,
		)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error reading token file: %v\n", err)
			return 1
		}
	}

	client := &cliClient{
		baseURL:    strings.TrimRight(apiURL, "/"),
		token:      resolvedToken,
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
	case "push":
		return runPush(ctx, client, apiURL, token, globalTokenExplicit, tokenFile, globalTokenFileExplicit, rest[1:], stdout, stderr)
	case "credential-helper":
		return runCredentialHelper(ctx, apiURL, apiURLExplicit, token, globalTokenExplicit, tokenFile, globalTokenFileExplicit, getenv, rest[1:], stdin, stdout, stderr)
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
		const evaluateUsage = "Usage: custodian policies evaluate --input <path> [--bundle <path>] [--org-bundle <path>] [--bundle-id <uuid>] [--stage INGRESS|EGRESS|PUSH_EGRESS]\n"
		fs := flag.NewFlagSet("policies evaluate", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		var bundlePath, orgPath, bundleID, inputPath, stage string
		var help bool
		fs.StringVar(&bundlePath, "bundle", "", "path to PolicyBundle YAML")
		fs.StringVar(&orgPath, "org-bundle", "", "path to ORG PolicyBundle YAML")
		fs.StringVar(&bundleID, "bundle-id", "", "persisted bundle UUIDv7")
		fs.StringVar(&inputPath, "input", "", "path to JSON simulation input")
		fs.StringVar(&stage, "stage", "EGRESS", "INGRESS, EGRESS, or PUSH_EGRESS")
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

func (c *cliClient) doRaw(ctx context.Context, method, path string, body any, idemKey string, requireIdem bool, stderr io.Writer) ([]byte, int, bool) {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error encoding request: %v\n", redactTokenFromString(err.Error(), c.token))
			return nil, 0, false
		}
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error building request: %v\n", redactTokenFromString(err.Error(), c.token))
		return nil, 0, false
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
				return nil, 0, false
			}
			key = id.String()
		}
		req.Header.Set("Idempotency-Key", key)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "request failed: %v\n", redactTokenFromString(err.Error(), c.token))
		return nil, 0, false
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error reading response: %v\n", redactTokenFromString(err.Error(), c.token))
		return nil, 0, false
	}

	if resp.StatusCode >= 400 {
		msg := redactTokenFromString(strings.TrimSpace(string(respBytes)), c.token)
		_, _ = fmt.Fprintf(stderr, "HTTP %d: %s\n", resp.StatusCode, msg)
		return respBytes, resp.StatusCode, false
	}
	return respBytes, resp.StatusCode, true
}

func (c *cliClient) doAndPrint(ctx context.Context, method, path string, body any, idemKey string, requireIdem bool, stdout, stderr io.Writer) int {
	respBytes, _, ok := c.doRaw(ctx, method, path, body, idemKey, requireIdem, stderr)
	if !ok {
		return 1
	}
	printPrettyJSON(respBytes, stdout)
	return 0
}

func printPrettyJSON(respBytes []byte, stdout io.Writer) {
	var pretty bytes.Buffer
	if json.Indent(&pretty, respBytes, "", "  ") == nil {
		_, _ = stdout.Write(append(pretty.Bytes(), '\n'))
	} else {
		_, _ = stdout.Write(respBytes)
		if len(respBytes) > 0 && respBytes[len(respBytes)-1] != '\n' {
			_, _ = io.WriteString(stdout, "\n")
		}
	}
}

func redactTokenFromString(s, token string) string {
	if token != "" {
		s = strings.ReplaceAll(s, token, "[REDACTED]")
	}
	return s
}

func readTokenFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil {
		return "", err
	}
	if len(data) > 64<<10 {
		return "", errors.New("token file exceeds 64 KiB limit")
	}
	tok := strings.TrimSpace(string(data))
	if tok == "" {
		return "", errors.New("token file is empty")
	}
	return tok, nil
}

func hasTokenControlOrSpace(token string) bool {
	if token == "" {
		return true
	}
	for _, r := range token {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func resolveCLIToken(
	subToken string, subTokenExplicit bool,
	subTokenFile string, subTokenFileExplicit bool,
	globalToken string, globalTokenExplicit bool,
	globalTokenFile string, globalTokenFileExplicit bool,
) (string, error) {
	if subTokenExplicit {
		return strings.TrimSpace(subToken), nil
	}
	if subTokenFileExplicit {
		return readTokenFile(strings.TrimSpace(subTokenFile))
	}
	if globalTokenExplicit {
		return strings.TrimSpace(globalToken), nil
	}
	if globalTokenFileExplicit {
		return readTokenFile(strings.TrimSpace(globalTokenFile))
	}
	if t := strings.TrimSpace(subToken); t != "" {
		return t, nil
	}
	if tf := strings.TrimSpace(subTokenFile); tf != "" {
		return readTokenFile(tf)
	}
	return "", nil
}

func runCredentialHelper(
	ctx context.Context,
	globalAPIURL string,
	apiURLExplicit bool,
	globalToken string,
	globalTokenExplicit bool,
	globalTokenFile string,
	globalTokenFileExplicit bool,
	getenv func(string) string,
	args []string,
	stdin io.Reader,
	stdout, stderr io.Writer,
) int {
	const credUsage = `Usage: custodian credential-helper [--api-url <url>] [--token <jwt>] [--token-file <path>] [--host <hosts>] [--allowed-hosts <hosts>] [--allow-insecure-http] <get|store|erase>
`
	fs := flag.NewFlagSet("credential-helper", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	apiURL := globalAPIURL
	token := globalToken
	tokenFile := globalTokenFile
	allowedHosts := strings.TrimSpace(getenv("CUSTODIAN_ALLOWED_HOSTS"))
	var hostFlag string
	var allowInsecureHTTP, help, subTokenExplicit, subTokenFileExplicit bool
	fs.StringVar(&apiURL, "api-url", apiURL, "Custodian API base URL")
	fs.StringVar(&token, "token", token, "Bearer OIDC JWT")
	fs.StringVar(&tokenFile, "token-file", tokenFile, "Path to Bearer token file")
	fs.StringVar(&hostFlag, "host", "", "Allowed host(s) comma-separated")
	fs.StringVar(&allowedHosts, "allowed-hosts", allowedHosts, "Allowed host(s) comma-separated")
	fs.BoolVar(&allowInsecureHTTP, "allow-insecure-http", false, "Allow non-loopback http:// git credential requests")
	fs.BoolVar(&help, "help", false, "show help")
	fs.BoolVar(&help, "h", false, "show help")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.WriteString(stdout, credUsage)
			return 0
		}
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "api-url":
			apiURLExplicit = true
		case "token":
			subTokenExplicit = true
		case "token-file":
			subTokenFileExplicit = true
		}
	})
	if help {
		_, _ = io.WriteString(stdout, credUsage)
		return 0
	}

	fsArgs := fs.Args()
	if len(fsArgs) == 0 {
		_, _ = io.WriteString(stderr, credUsage)
		return 2
	}
	if isHelpArg(fsArgs[0]) {
		_, _ = io.WriteString(stdout, credUsage)
		return 0
	}
	if len(fsArgs) != 1 {
		_, _ = io.WriteString(stderr, credUsage)
		return 2
	}

	op := fsArgs[0]
	switch op {
	case "store", "erase":
		_, _ = io.Copy(io.Discard, io.LimitReader(stdin, 64<<10))
		return 0
	case "get":
		// handled below
	default:
		_, _ = fmt.Fprintf(stderr, "unknown credential-helper operation %q\n", op)
		return 2
	}

	proto, host, err := parseGitCredentialInput(stdin, allowInsecureHTTP)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "credential-helper error: %v\n", err)
		return 1
	}

	effectiveAllowlist := mergeHostAllowlists(allowedHosts, hostFlag)
	if len(effectiveAllowlist) > 0 && !hostInAllowlist(host, effectiveAllowlist) {
		return 0
	}

	if !apiURLExplicit || strings.TrimSpace(apiURL) == "" {
		_, _ = fmt.Fprintln(stderr, "credential-helper error: CUSTODIAN_API_URL or --api-url is required")
		return 1
	}
	parsedAPI, err := url.Parse(strings.TrimSpace(apiURL))
	if err != nil || (parsedAPI.Scheme != "http" && parsedAPI.Scheme != "https") || strings.TrimSpace(parsedAPI.Host) == "" {
		_, _ = fmt.Fprintln(stderr, "credential-helper error: invalid Custodian API URL")
		return 1
	}

	resolvedToken, tokErr := resolveCLIToken(
		token, subTokenExplicit,
		tokenFile, subTokenFileExplicit,
		globalToken, globalTokenExplicit,
		globalTokenFile, globalTokenFileExplicit,
	)
	if tokErr != nil {
		_, _ = fmt.Fprintf(stderr, "credential-helper error: %v\n", tokErr)
		return 1
	}
	if hasTokenControlOrSpace(resolvedToken) {
		_, _ = fmt.Fprintln(stderr, "credential-helper error: missing or invalid OIDC token")
		return 1
	}

	verifyClient := &http.Client{Timeout: 10 * time.Second}
	verifyURL := strings.TrimRight(strings.TrimSpace(apiURL), "/") + "/v1/pushes?limit=1"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, verifyURL, nil)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "credential-helper error: %v\n", redactTokenFromString(err.Error(), resolvedToken))
		return 1
	}
	req.Header.Set("Authorization", "Bearer "+resolvedToken)

	resp, err := verifyClient.Do(req)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "credential-helper verification failed: %v\n", redactTokenFromString(err.Error(), resolvedToken))
		return 1
	}
	defer resp.Body.Close()
	respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		msg := redactTokenFromString(strings.TrimSpace(string(respBody)), resolvedToken)
		_, _ = fmt.Fprintf(stderr, "credential-helper authentication rejected (HTTP %d): %s\n", resp.StatusCode, msg)
		return 1
	}
	if readErr != nil {
		_, _ = fmt.Fprintf(stderr, "credential-helper verification failed: %v\n", redactTokenFromString(readErr.Error(), resolvedToken))
		return 1
	}
	if ct := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Type"))); ct != "" && !strings.Contains(ct, "json") {
		_, _ = fmt.Fprintf(stderr, "credential-helper verification failed: unexpected Content-Type %q\n", redactTokenFromString(ct, resolvedToken))
		return 1
	}
	var probe struct {
		Pushes *[]json.RawMessage `json:"pushes"`
	}
	if err := json.Unmarshal(respBody, &probe); err != nil || probe.Pushes == nil {
		_, _ = fmt.Fprintln(stderr, "credential-helper verification failed: unexpected response payload from Custodian API")
		return 1
	}

	if hasCRLFOrNul(proto) || hasCRLFOrNul(host) || hasCRLFOrNul(resolvedToken) {
		_, _ = fmt.Fprintln(stderr, "credential-helper error: output contains disallowed control characters")
		return 1
	}

	out := fmt.Sprintf("protocol=%s\nhost=%s\nusername=x-access-token\npassword=%s\n", proto, host, resolvedToken)
	_, _ = io.WriteString(stdout, out)
	return 0
}

func hasCRLFOrNul(s string) bool {
	return strings.ContainsAny(s, "\r\n\x00")
}

func parseGitCredentialInput(r io.Reader, allowInsecureHTTP bool) (string, string, error) {
	raw, err := io.ReadAll(io.LimitReader(r, (64<<10)+1))
	if err != nil {
		return "", "", fmt.Errorf("reading stdin: %w", err)
	}
	if len(raw) > 64<<10 {
		return "", "", errors.New("credential input exceeds 64 KiB limit")
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return "", "", errors.New("empty credential input")
	}
	rawStr := string(raw)
	if !utf8.ValidString(rawStr) {
		return "", "", errors.New("invalid UTF-8 in credential input")
	}
	for _, r := range rawStr {
		if r == '\n' || r == ' ' {
			continue
		}
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return "", "", errors.New("disallowed control or whitespace character in credential input")
		}
	}

	attrs := make(map[string]string)
	lines := strings.Split(rawStr, "\n")
	for _, line := range lines {
		if line == "" {
			break
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || !isValidCredentialKey(k) {
			return "", "", errors.New("malformed credential line")
		}
		switch k {
		case "host", "protocol", "url":
			if _, exists := attrs[k]; exists {
				return "", "", fmt.Errorf("duplicate credential attribute %q", k)
			}
		}
		attrs[k] = v
	}
	if len(attrs) == 0 {
		return "", "", errors.New("empty credential attributes")
	}

	proto := strings.ToLower(attrs["protocol"])
	host := attrs["host"]
	if host == "" {
		if rawURL := attrs["url"]; rawURL != "" {
			u, uErr := url.Parse(rawURL)
			if uErr != nil || u.Host == "" {
				return "", "", errors.New("invalid credential url")
			}
			host = u.Host
			if proto == "" {
				proto = strings.ToLower(u.Scheme)
			}
		}
	}

	if host == "" {
		return "", "", errors.New("missing credential host")
	}
	for _, r := range host {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return "", "", errors.New("invalid credential host")
		}
	}
	if strings.ContainsAny(host, "/\\@?#=") {
		return "", "", errors.New("invalid credential host")
	}
	if proto == "" {
		proto = "https"
	}
	switch proto {
	case "https":
	case "http":
		if !allowInsecureHTTP && !isLoopbackHost(host) {
			return "", "", errors.New("insecure http protocol requires loopback host or --allow-insecure-http")
		}
	default:
		return "", "", fmt.Errorf("unsupported credential protocol %q", proto)
	}
	return proto, host, nil
}

func isValidCredentialKey(k string) bool {
	if k == "" {
		return false
	}
	for _, r := range k {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '.' || r == '-' || r == '[' || r == ']' {
			continue
		}
		return false
	}
	return true
}

func isLoopbackHost(hostport string) bool {
	h := hostport
	if parsedHost, _, err := net.SplitHostPort(hostport); err == nil {
		h = parsedHost
	}
	h = strings.Trim(h, "[]")
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func mergeHostAllowlists(a, b string) []string {
	var out []string
	for _, raw := range []string{a, b} {
		for _, part := range strings.Split(raw, ",") {
			trimmed := strings.ToLower(strings.TrimSpace(part))
			if trimmed != "" {
				out = append(out, trimmed)
			}
		}
	}
	return out
}

func splitNormalizeHostPort(raw string) (host, port string, hasPort bool) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if h, p, err := net.SplitHostPort(s); err == nil {
		return strings.Trim(h, "[]"), p, true
	}
	return strings.Trim(s, "[]"), "", false
}

func hostInAllowlist(hostport string, allowlist []string) bool {
	reqHost, reqPort, reqHasPort := splitNormalizeHostPort(hostport)
	if reqHost == "" {
		return false
	}
	for _, allowed := range allowlist {
		alHost, alPort, alHasPort := splitNormalizeHostPort(allowed)
		if alHost == "" {
			continue
		}
		if alHasPort {
			if reqHasPort && reqHost == alHost && reqPort == alPort {
				return true
			}
			continue
		}
		if reqHost == alHost {
			return true
		}
	}
	return false
}

func runPush(ctx context.Context, client *cliClient, apiURL, token string, tokenExplicit bool, tokenFile string, tokenFileExplicit bool, args []string, stdout, stderr io.Writer) int {
	const pushUsage = "Usage: custodian push <status> ...\n"
	if len(args) == 0 || isHelpArg(args[0]) {
		_, _ = io.WriteString(stdout, pushUsage)
		return 0
	}
	switch args[0] {
	case "status":
		return runPushStatus(ctx, client, apiURL, token, tokenExplicit, tokenFile, tokenFileExplicit, args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "unknown push subcommand %q\n", args[0])
		return 2
	}
}

func runPushStatus(ctx context.Context, baseClient *cliClient, globalAPIURL, globalToken string, globalTokenExplicit bool, globalTokenFile string, globalTokenFileExplicit bool, args []string, stdout, stderr io.Writer) int {
	const statusUsage = `Usage:
  custodian push status [<id>] [--push-id <id>] [--id <id>] [--format json|text]
  custodian push status [--repository-id <uuid>] [--principal-id <uuid>] [--status <status>] [--egress-mode <mode>] [--cursor <uuid>] [--limit <n>] [--format json|text]
`
	if hasHelpArg(args) {
		_, _ = io.WriteString(stdout, statusUsage)
		return 0
	}

	var posID string
	parseArgs := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		posID = args[0]
		parseArgs = args[1:]
	}

	fs := flag.NewFlagSet("push status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var pushIDFlag, idFlag, repoID, principalID, statusFilter, egressMode, cursor, format string
	var limit int
	var apiURL, token, tokenFile string
	var subTokenExplicit, subTokenFileExplicit bool
	fs.StringVar(&pushIDFlag, "push-id", "", "Push session UUIDv7")
	fs.StringVar(&idFlag, "id", "", "Push session UUIDv7 (alias for --push-id)")
	fs.StringVar(&repoID, "repository-id", "", "Repository UUIDv7 filter")
	fs.StringVar(&principalID, "principal-id", "", "Principal UUIDv7 filter")
	fs.StringVar(&statusFilter, "status", "", "Push session status filter")
	fs.StringVar(&egressMode, "egress-mode", "", "Egress mode filter")
	fs.StringVar(&cursor, "cursor", "", "Pagination cursor")
	fs.IntVar(&limit, "limit", 0, "Maximum push sessions to return")
	fs.StringVar(&format, "format", "json", "Output format (json|text)")
	fs.StringVar(&apiURL, "api-url", globalAPIURL, "Custodian API base URL")
	fs.StringVar(&token, "token", globalToken, "Bearer OIDC JWT")
	fs.StringVar(&tokenFile, "token-file", globalTokenFile, "Path to Bearer token file")

	if err := fs.Parse(parseArgs); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.WriteString(stdout, statusUsage)
			return 0
		}
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "token":
			subTokenExplicit = true
		case "token-file":
			subTokenFileExplicit = true
		}
	})

	if fs.NArg() > 0 {
		if posID != "" || fs.NArg() > 1 {
			_, _ = io.WriteString(stderr, statusUsage)
			return 2
		}
		posID = fs.Arg(0)
	}

	format = strings.ToLower(strings.TrimSpace(format))
	if format != "json" && format != "text" {
		_, _ = fmt.Fprintf(stderr, "error: --format must be json or text (got %q)\n", format)
		return 2
	}

	if pushIDFlag != "" && idFlag != "" && pushIDFlag != idFlag {
		_, _ = fmt.Fprintln(stderr, "error: --push-id and --id must not conflict")
		return 2
	}
	targetID := pushIDFlag
	if targetID == "" {
		targetID = idFlag
	}
	if targetID != "" && posID != "" && targetID != posID {
		_, _ = fmt.Fprintln(stderr, "error: positional push ID conflicts with --push-id/--id flag")
		return 2
	}
	if targetID == "" {
		targetID = posID
	}

	if limit < 0 {
		_, _ = fmt.Fprintln(stderr, "error: --limit must be non-negative")
		return 2
	}

	hasListFilters := repoID != "" || principalID != "" || statusFilter != "" || egressMode != "" || cursor != "" || limit > 0
	if targetID != "" && hasListFilters {
		_, _ = fmt.Fprintln(stderr, "error: cannot combine push ID with list filter flags")
		return 2
	}

	resolvedToken, err := resolveCLIToken(
		token, subTokenExplicit,
		tokenFile, subTokenFileExplicit,
		globalToken, globalTokenExplicit,
		globalTokenFile, globalTokenFileExplicit,
	)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error reading token file: %v\n", err)
		return 1
	}

	client := &cliClient{
		baseURL:    strings.TrimRight(strings.TrimSpace(apiURL), "/"),
		token:      resolvedToken,
		httpClient: baseClient.httpClient,
	}

	if targetID != "" {
		p := "/v1/pushes/" + url.PathEscape(targetID)
		respBytes, _, ok := client.doRaw(ctx, http.MethodGet, p, nil, "", false, stderr)
		if !ok {
			return 1
		}
		if format == "json" {
			printPrettyJSON(respBytes, stdout)
			return 0
		}
		return renderPushStatusText(respBytes, stdout, stderr)
	}

	q := url.Values{}
	if repoID != "" {
		q.Set("repository_id", repoID)
	}
	if principalID != "" {
		q.Set("principal_id", principalID)
	}
	if statusFilter != "" {
		q.Set("status", statusFilter)
	}
	if egressMode != "" {
		q.Set("egress_mode", egressMode)
	}
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	if limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", limit))
	}
	p := "/v1/pushes"
	if enc := q.Encode(); enc != "" {
		p += "?" + enc
	}
	respBytes, _, ok := client.doRaw(ctx, http.MethodGet, p, nil, "", false, stderr)
	if !ok {
		return 1
	}
	if format == "json" {
		printPrettyJSON(respBytes, stdout)
		return 0
	}
	return renderPushListText(respBytes, stdout, stderr)
}

type cliPushSessionView struct {
	ID                     string `json:"id"`
	Status                 string `json:"status"`
	PolicyEffect           string `json:"policy_effect"`
	Verdict                string `json:"verdict"`
	EgressMode             string `json:"egress_mode"`
	Enforced               bool   `json:"enforced"`
	Destination            string `json:"destination"`
	PushManifestDigest     string `json:"push_manifest_digest"`
	UpstreamForwarded      bool   `json:"upstream_forwarded"`
	UpstreamBytesSent      int64  `json:"upstream_bytes_sent"`
	ApprovalReleaseID      string `json:"approval_release_id"`
	LatestPolicyDecisionID string `json:"latest_policy_decision_id"`
	PolicyDecisionID       string `json:"policy_decision_id"`
	ErrorCode              string `json:"error_code"`
	ErrorMessage           string `json:"error_message"`
}

func (v cliPushSessionView) effectiveVerdict() string {
	if v.PolicyEffect != "" {
		return v.PolicyEffect
	}
	return v.Verdict
}

func renderPushStatusText(raw []byte, stdout, stderr io.Writer) int {
	var v cliPushSessionView
	if err := json.Unmarshal(raw, &v); err != nil {
		_, _ = fmt.Fprintf(stderr, "error decoding push session response: %v\n", err)
		return 1
	}
	verdict := v.effectiveVerdict()
	if verdict == "" {
		verdict = "PENDING"
	}
	decisionID := v.PolicyDecisionID
	if decisionID == "" {
		decisionID = v.LatestPolicyDecisionID
	}

	_, _ = fmt.Fprintf(stdout, "Push ID:            %s\n", v.ID)
	_, _ = fmt.Fprintf(stdout, "Status:             %s\n", v.Status)
	_, _ = fmt.Fprintf(stdout, "Verdict:            %s\n", verdict)
	_, _ = fmt.Fprintf(stdout, "Egress Mode:        %s (enforced=%t)\n", v.EgressMode, v.Enforced)
	_, _ = fmt.Fprintf(stdout, "Destination:        %s\n", v.Destination)
	if v.PushManifestDigest != "" {
		_, _ = fmt.Fprintf(stdout, "Manifest Digest:    %s\n", v.PushManifestDigest)
	}
	_, _ = fmt.Fprintf(stdout, "Upstream Forwarded: %t (bytes=%d)\n", v.UpstreamForwarded, v.UpstreamBytesSent)
	if decisionID != "" {
		_, _ = fmt.Fprintf(stdout, "Policy Decision ID: %s\n", decisionID)
	}
	if v.ApprovalReleaseID != "" {
		_, _ = fmt.Fprintf(stdout, "Approval Release:   %s\n", v.ApprovalReleaseID)
	}
	if v.ErrorCode != "" || v.ErrorMessage != "" {
		_, _ = fmt.Fprintf(stdout, "Error:              %s %s\n", v.ErrorCode, v.ErrorMessage)
	}

	switch {
	case v.Status == "OBSERVED_WOULD_BLOCK":
		_, _ = fmt.Fprintln(stdout, "Next Steps:         PASSIVE_AUDIT observed policy violations that would block under ENFORCE_BLOCK; remediate before enforcement.")
	case v.Status == "FAILED":
		_, _ = fmt.Fprintln(stdout, "Next Steps:         Push gateway processing or upstream forwarding failed; inspect error details and retry.")
	case v.Status == "APPROVAL_REQUIRED":
		_, _ = fmt.Fprintf(stdout, "Next Steps:         Awaiting human approval release via POST /v1/pushes/%s/approvals (push_manifest_digest=%s), then re-run git push.\n", v.ID, v.PushManifestDigest)
	case v.Status == "BLOCKED":
		_, _ = fmt.Fprintln(stdout, "Next Steps:         Push was blocked by policy. Remediate findings or contact a security admin before re-pushing.")
	case v.Status == "QUARANTINED":
		_, _ = fmt.Fprintln(stdout, "Next Steps:         Push is quarantined pending security investigation; zero bytes were sent upstream.")
	case v.Status == "COMPLETED":
		_, _ = fmt.Fprintln(stdout, "Next Steps:         Push allowed and completed.")
	case verdict == "REQUIRE_APPROVAL":
		_, _ = fmt.Fprintf(stdout, "Next Steps:         Awaiting human approval release via POST /v1/pushes/%s/approvals (push_manifest_digest=%s), then re-run git push.\n", v.ID, v.PushManifestDigest)
	case verdict == "DENY":
		_, _ = fmt.Fprintln(stdout, "Next Steps:         Push was blocked by policy. Remediate findings or contact a security admin before re-pushing.")
	case verdict == "QUARANTINE":
		_, _ = fmt.Fprintln(stdout, "Next Steps:         Push is quarantined pending security investigation; zero bytes were sent upstream.")
	case verdict == "ALLOW":
		_, _ = fmt.Fprintln(stdout, "Next Steps:         Push allowed and completed.")
	}
	return 0
}

func renderPushListText(raw []byte, stdout, stderr io.Writer) int {
	var resp struct {
		Pushes     []cliPushSessionView `json:"pushes"`
		NextCursor string               `json:"next_cursor"`
		HasMore    bool                 `json:"has_more"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		_, _ = fmt.Fprintf(stderr, "error decoding push list response: %v\n", err)
		return 1
	}
	if len(resp.Pushes) == 0 {
		_, _ = io.WriteString(stdout, "No push sessions found.\n")
		return 0
	}
	for _, p := range resp.Pushes {
		verdict := p.effectiveVerdict()
		if verdict == "" {
			verdict = "-"
		}
		_, _ = fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\t%s\tdigest=%s\tforwarded=%t\n",
			p.ID, p.Status, verdict, p.EgressMode, p.Destination, p.PushManifestDigest, p.UpstreamForwarded)
	}
	if resp.HasMore && resp.NextCursor != "" {
		_, _ = fmt.Fprintf(stdout, "Next Cursor: %s\n", resp.NextCursor)
	}
	return 0
}
