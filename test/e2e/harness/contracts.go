package harness

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// BinaryNames maps logical Custodian components to executable names.
type BinaryNames struct {
	Custodian  string `json:"custodian"`
	API        string `json:"api"`
	Worker     string `json:"worker"`
	Publisher  string `json:"publisher"`
	Policy     string `json:"policy"`
	GitGateway string `json:"git_gateway"`
}

// StatusSet groups lifecycle status literals for polling and assertion helpers.
type StatusSet struct {
	Pending         string   `json:"pending"`
	Ready           string   `json:"ready"`
	TerminalSuccess []string `json:"terminal_success"`
	TerminalFailure []string `json:"terminal_failure"`
	Denied          string   `json:"denied"`
	Quarantined     string   `json:"quarantined"`
}

// ProposalStatusSet extends StatusSet with additional proposal-specific lifecycle states.
type ProposalStatusSet struct {
	StatusSet
	Reconstructing      string `json:"reconstructing"`
	Evaluating          string `json:"evaluating"`
	PendingApproval     string `json:"pending_approval"`
	RemediationRequired string `json:"remediation_required"`
	Publishing          string `json:"publishing"`
}

// Contains reports whether status matches any entry in list (case-insensitive).
func ContainsStatus(list []string, status string) bool {
	for _, s := range list {
		if strings.EqualFold(s, status) {
			return true
		}
	}
	return false
}

// AuditQueryConfig defines query parameter names for GET /v1/audit/events.
type AuditQueryConfig struct {
	ResourceTypeParam string `json:"resource_type_param"`
	ResourceIDParam   string `json:"resource_id_param"`
	EventTypeParam    string `json:"event_type_param"`
	ActorIDParam      string `json:"actor_id_param"`
	SinceParam        string `json:"since_param"`
	UntilParam        string `json:"until_param"`
	LimitParam        string `json:"limit_param"`
	CursorParam       string `json:"cursor_param"`
}

// PushEndpointConfig defines relative /v1 paths for Push Gateway control-plane endpoints.
type PushEndpointConfig struct {
	PushesPath          string `json:"pushes_path"`
	PushByIDPath        string `json:"push_by_id_path"`
	PushApprovalsPath   string `json:"push_approvals_path"`
	RepoEgressModePath  string `json:"repo_egress_mode_path"`
	IPCorporaPath       string `json:"ip_corpora_path"`
	IPCorpusReindexPath string `json:"ip_corpus_reindex_path"`
}

// CLIConfig centralizes CLI subcommand/flag conventions for custodian and custodian-policy.
type CLIConfig struct {
	PolicyValidateSubcommand   []string          `json:"policy_validate_subcommand"`
	PolicyEvaluateSubcommand   []string          `json:"policy_evaluate_subcommand"`
	PolicyTestSubcommand       []string          `json:"policy_test_subcommand"`
	CredentialHelperSubcommand []string          `json:"credential_helper_subcommand"`
	PushSubcommand             []string          `json:"push_subcommand"`
	PushStatusSubcommand       []string          `json:"push_status_subcommand"`
	PolicyBundleFlag           string            `json:"policy_bundle_flag"`
	PolicyInputFlag            string            `json:"policy_input_flag"`
	ScannerBinEnvVars          map[string]string `json:"scanner_bin_env_vars"`
}

// Contracts centralizes all OpenAPI-bound and binary-bound wire details so E2E tests
// can synchronize with api/openapi.yaml and cmd/* without rewriting test assertions.
type Contracts struct {
	// REST API Paths & Transport
	APIBasePath                string             `json:"api_base_path"`
	HealthPath                 string             `json:"health_path"`
	ReadyPath                  string             `json:"ready_path"`
	MetricsPath                string             `json:"metrics_path"`
	SourceDownloadMode         string             `json:"source_download_mode"` // "auto" | "descriptor_then_get" | "direct_binary"
	UploadCapabilityMethod     string             `json:"upload_capability_method"`
	UploadCapabilityHeader     string             `json:"upload_capability_header"`
	UploadCapabilityBearer     bool               `json:"upload_capability_bearer"`
	UploadCapabilityURLField   string             `json:"upload_capability_url_field"`
	UploadCapabilityEndpoint   string             `json:"upload_capability_endpoint"`
	OptimisticVersionTransport string             `json:"optimistic_version_transport"` // "both" | "body" | "if_match_header"
	PushEndpoints              PushEndpointConfig `json:"push_endpoints"`

	// Status Enums
	WorkspaceStatuses   StatusSet         `json:"workspace_statuses"`
	ProposalStatuses    ProposalStatusSet `json:"proposal_statuses"`
	OperationStatuses   StatusSet         `json:"operation_statuses"`
	PublicationStatuses StatusSet         `json:"publication_statuses"`
	PushStatuses        StatusSet         `json:"push_statuses"`

	// Query Parameter Names
	AuditQueryParams AuditQueryConfig `json:"audit_query_params"`

	// Gateway & Scanner Wire Formats
	GatewayPath             string `json:"gateway_path"`
	GatewayResponseFormat   string `json:"gateway_response_format"`   // "auto" | "raw_json" | "openai_chat"
	GatewayCleanDisposition string `json:"gateway_clean_disposition"` // "CLEAR" per api/schemas/inspection.yaml
	ScannerSkippedMode      string `json:"scanner_skipped_mode"`      // "native" | "stderr" | "nonzero"

	// Runtime Environment & Process Launch Contract
	Binaries             BinaryNames `json:"binaries"`
	EnvListenAddr        string      `json:"env_listen_addr"`
	EnvDatabaseDSN       string      `json:"env_database_dsn"`
	EnvOIDCIssuer        string      `json:"env_oidc_issuer"`
	EnvOIDCJWKSURL       string      `json:"env_oidc_jwks_url"`
	EnvOIDCAudience      string      `json:"env_oidc_audience"`
	EnvGitHubAPIBaseURL  string      `json:"env_github_api_base_url"`
	EnvGitHubReadAppID   string      `json:"env_github_read_app_id"`
	EnvGitHubReadKeyPEM  string      `json:"env_github_read_key_pem"`
	EnvGitHubWriteAppID  string      `json:"env_github_write_app_id"`
	EnvGitHubWriteKeyPEM string      `json:"env_github_write_key_pem"`
	EnvSnapshotStoreRoot string      `json:"env_snapshot_store_root"`
	EnvSnapshotStoreKind string      `json:"env_snapshot_store_kind"`
	EnvModelGatewayURL   string      `json:"env_model_gateway_url"`
	EnvCapabilitySecret  string      `json:"env_capability_secret"`
	EnvRepoConcurrency   string      `json:"env_repo_concurrency"`
	EnvGlobalScanBudget  string      `json:"env_global_scan_budget"`
	EnvGlobalModelBudget string      `json:"env_global_model_budget"`
	EnvArtifactRetention string      `json:"env_artifact_retention"`
	EnvLogFormat         string      `json:"env_log_format"`
	EnvLogLevel          string      `json:"env_log_level"`
	EnvPolicyBundleDir   string      `json:"env_policy_bundle_dir"`

	// Push Gateway Environment Variables
	EnvGitGatewayHTTPAddr          string `json:"env_git_gateway_http_addr"`
	EnvGitGatewaySSHAddr           string `json:"env_git_gateway_ssh_addr"`
	EnvGitGatewayTLSCertFile       string `json:"env_git_gateway_tls_cert_file"`
	EnvGitGatewayTLSKeyFile        string `json:"env_git_gateway_tls_key_file"`
	EnvGitGatewaySSHHostKeyFile    string `json:"env_git_gateway_ssh_host_key_file"`
	EnvGitGatewaySSHUserCAFile     string `json:"env_git_gateway_ssh_user_ca_file"`
	EnvGitGatewayUpstreamURL       string `json:"env_git_gateway_upstream_url"`
	EnvGitGatewayAPIBaseURL        string `json:"env_git_gateway_api_base_url"`
	EnvGitGatewayMaxPackBytes      string `json:"env_git_gateway_max_pack_bytes"`
	EnvGitGatewayMaxObjects        string `json:"env_git_gateway_max_objects"`
	EnvGitGatewayMaxInflatedBytes  string `json:"env_git_gateway_max_inflated_bytes"`
	EnvGitGatewayMaxRefUpdates     string `json:"env_git_gateway_max_ref_updates"`
	EnvGitGatewayDefaultEgressMode string `json:"env_git_gateway_default_egress_mode"`
	EnvGitGatewayPassiveDelivery   string `json:"env_git_gateway_passive_delivery"`

	APIArgs        []string `json:"api_args"`
	WorkerArgs     []string `json:"worker_args"`
	PublisherArgs  []string `json:"publisher_args"`
	GitGatewayArgs []string `json:"git_gateway_args,omitempty"`

	// CLI Subcommands & Flags
	CLI CLIConfig `json:"cli"`
}

// DefaultContracts returns the canonical default wire and runtime contract aligned with Spec §§1–16.
func DefaultContracts() *Contracts {
	return &Contracts{
		APIBasePath:                "/v1",
		HealthPath:                 "/healthz",
		ReadyPath:                  "/readyz",
		MetricsPath:                "/metrics",
		SourceDownloadMode:         "auto",
		UploadCapabilityMethod:     "PUT",
		UploadCapabilityHeader:     "Authorization",
		UploadCapabilityBearer:     true,
		UploadCapabilityURLField:   "upload_url",
		OptimisticVersionTransport: "both",
		PushEndpoints: PushEndpointConfig{
			PushesPath:          "/pushes",
			PushByIDPath:        "/pushes/{id}",
			PushApprovalsPath:   "/pushes/{id}/approvals",
			RepoEgressModePath:  "/repositories/{id}/egress-mode",
			IPCorporaPath:       "/ip-corpora",
			IPCorpusReindexPath: "/ip-corpora/{id}/reindex",
		},

		WorkspaceStatuses: StatusSet{
			Pending:         "PENDING",
			Ready:           "READY",
			TerminalSuccess: []string{"READY", "ACTIVE", "COMPLETED"},
			TerminalFailure: []string{"FAILED", "DENIED", "CLOSED"},
			Denied:          "DENIED",
		},
		ProposalStatuses: ProposalStatusSet{
			StatusSet: StatusSet{
				Pending:         "CAPTURED",
				Ready:           "RECONSTRUCTED",
				TerminalSuccess: []string{"PUBLISHED", "APPROVED"},
				TerminalFailure: []string{"DENIED", "QUARANTINED", "FAILED", "REJECTED"},
				Denied:          "DENIED",
				Quarantined:     "QUARANTINED",
			},
			Reconstructing:      "RECONSTRUCTING",
			Evaluating:          "EVALUATING",
			PendingApproval:     "PENDING_APPROVAL",
			RemediationRequired: "REMEDIATION_REQUIRED",
			Publishing:          "PUBLISHING",
		},
		OperationStatuses: StatusSet{
			Pending:         "PENDING",
			Ready:           "RUNNING",
			TerminalSuccess: []string{"COMPLETED", "SUCCEEDED", "DONE"},
			TerminalFailure: []string{"FAILED", "CANCELLED", "DENIED"},
		},
		PublicationStatuses: StatusSet{
			Pending:         "PENDING",
			Ready:           "PUBLISHED",
			TerminalSuccess: []string{"PUBLISHED", "COMPLETED", "SUCCEEDED"},
			TerminalFailure: []string{"FAILED", "ABORTED"},
		},
		PushStatuses: StatusSet{
			Pending:         "RECEIVED",
			Ready:           "ALLOWED",
			TerminalSuccess: []string{"ALLOWED", "FORWARDED", "PUBLISHED", "COMPLETED"},
			TerminalFailure: []string{"DENIED", "BLOCKED", "QUARANTINED", "FAILED", "REJECTED"},
			Denied:          "DENIED",
			Quarantined:     "QUARANTINED",
		},

		AuditQueryParams: AuditQueryConfig{
			ResourceTypeParam: "resource_type",
			ResourceIDParam:   "resource_id",
			EventTypeParam:    "event_type",
			ActorIDParam:      "actor_id",
			SinceParam:        "since",
			UntilParam:        "until",
			LimitParam:        "limit",
			CursorParam:       "cursor",
		},

		GatewayPath:             "/v1/assess",
		GatewayResponseFormat:   "auto",
		GatewayCleanDisposition: "CLEAR",
		ScannerSkippedMode:      "native",

		Binaries: BinaryNames{
			Custodian:  "custodian",
			API:        "custodian-api",
			Worker:     "custodian-worker",
			Publisher:  "custodian-publisher",
			Policy:     "custodian-policy",
			GitGateway: "custodian-git-gateway",
		},
		EnvListenAddr:                  "CUSTODIAN_LISTEN_ADDR",
		EnvDatabaseDSN:                 "CUSTODIAN_DATABASE_URL",
		EnvOIDCIssuer:                  "CUSTODIAN_OIDC_ISSUER",
		EnvOIDCJWKSURL:                 "CUSTODIAN_OIDC_JWKS_URL",
		EnvOIDCAudience:                "CUSTODIAN_OIDC_AUDIENCE",
		EnvGitHubAPIBaseURL:            "CUSTODIAN_GITHUB_API_URL",
		EnvGitHubReadAppID:             "CUSTODIAN_GITHUB_READ_APP_ID",
		EnvGitHubReadKeyPEM:            "CUSTODIAN_GITHUB_READ_PRIVATE_KEY_PEM",
		EnvGitHubWriteAppID:            "CUSTODIAN_GITHUB_WRITE_APP_ID",
		EnvGitHubWriteKeyPEM:           "CUSTODIAN_GITHUB_WRITE_PRIVATE_KEY_PEM",
		EnvSnapshotStoreRoot:           "CUSTODIAN_SNAPSHOT_DIR",
		EnvSnapshotStoreKind:           "CUSTODIAN_SNAPSHOT_STORE",
		EnvModelGatewayURL:             "CUSTODIAN_MODEL_GATEWAY_URL",
		EnvCapabilitySecret:            "CUSTODIAN_CAPABILITY_HMAC_SECRET",
		EnvRepoConcurrency:             "CUSTODIAN_REPO_CONCURRENCY_LIMIT",
		EnvGlobalScanBudget:            "CUSTODIAN_GLOBAL_SCAN_BUDGET",
		EnvGlobalModelBudget:           "CUSTODIAN_GLOBAL_MODEL_BUDGET",
		EnvArtifactRetention:           "CUSTODIAN_ARTIFACT_RETENTION_TTL",
		EnvLogFormat:                   "CUSTODIAN_LOG_FORMAT",
		EnvLogLevel:                    "CUSTODIAN_LOG_LEVEL",
		EnvPolicyBundleDir:             "CUSTODIAN_POLICY_DIR",
		EnvGitGatewayHTTPAddr:          "CUSTODIAN_GIT_GATEWAY_HTTP_ADDR",
		EnvGitGatewaySSHAddr:           "CUSTODIAN_GIT_GATEWAY_SSH_ADDR",
		EnvGitGatewayTLSCertFile:       "CUSTODIAN_GIT_GATEWAY_TLS_CERT_FILE",
		EnvGitGatewayTLSKeyFile:        "CUSTODIAN_GIT_GATEWAY_TLS_KEY_FILE",
		EnvGitGatewaySSHHostKeyFile:    "CUSTODIAN_GIT_GATEWAY_SSH_HOST_KEY_FILE",
		EnvGitGatewaySSHUserCAFile:     "CUSTODIAN_GIT_GATEWAY_SSH_USER_CA_FILE",
		EnvGitGatewayUpstreamURL:       "CUSTODIAN_GIT_GATEWAY_UPSTREAM_URL",
		EnvGitGatewayAPIBaseURL:        "CUSTODIAN_GIT_GATEWAY_API_BASE_URL",
		EnvGitGatewayMaxPackBytes:      "CUSTODIAN_GIT_GATEWAY_MAX_PACK_BYTES",
		EnvGitGatewayMaxObjects:        "CUSTODIAN_GIT_GATEWAY_MAX_OBJECTS",
		EnvGitGatewayMaxInflatedBytes:  "CUSTODIAN_GIT_GATEWAY_MAX_INFLATED_BYTES",
		EnvGitGatewayMaxRefUpdates:     "CUSTODIAN_GIT_GATEWAY_MAX_REF_UPDATES",
		EnvGitGatewayDefaultEgressMode: "CUSTODIAN_GIT_GATEWAY_DEFAULT_EGRESS_MODE",
		EnvGitGatewayPassiveDelivery:   "CUSTODIAN_GIT_GATEWAY_PASSIVE_DELIVERY",

		CLI: CLIConfig{
			PolicyValidateSubcommand:   []string{"validate"},
			PolicyEvaluateSubcommand:   []string{"evaluate"},
			PolicyTestSubcommand:       []string{"test"},
			CredentialHelperSubcommand: []string{"credential-helper"},
			PushSubcommand:             []string{"push"},
			PushStatusSubcommand:       []string{"push", "status"},
			PolicyBundleFlag:           "--bundle",
			PolicyInputFlag:            "--input",
			ScannerBinEnvVars: map[string]string{
				"gitleaks": "CUSTODIAN_GITLEAKS_BIN",
				"scancode": "CUSTODIAN_SCANCODE_BIN",
				"semgrep":  "CUSTODIAN_SEMGREP_BIN",
				"trivy":    "CUSTODIAN_TRIVY_BIN",
			},
		},
	}
}

// Clone returns a deep copy of Contracts so per-test overrides do not mutate shared state.
func (c *Contracts) Clone() *Contracts {
	if c == nil {
		return DefaultContracts()
	}
	raw, err := json.Marshal(c)
	if err != nil {
		cp := *c
		return &cp
	}
	var out Contracts
	if err := json.Unmarshal(raw, &out); err != nil {
		cp := *c
		return &cp
	}
	return &out
}

// LoadContracts builds a Contracts instance by merging DefaultContracts(), an optional
// JSON overlay ($CUSTODIAN_E2E_CONTRACTS, <repoRoot>/test/e2e/contracts.json, or ./contracts.json),
// and explicit environment variable overrides.
func LoadContracts(repoRoot string) (*Contracts, error) {
	c := DefaultContracts()

	envPath := strings.TrimSpace(os.Getenv("CUSTODIAN_E2E_CONTRACTS"))
	var candidates []string
	if envPath != "" {
		candidates = append(candidates, envPath)
	}
	if repoRoot != "" {
		candidates = append(candidates, filepath.Join(repoRoot, "test", "e2e", "contracts.json"))
	}
	candidates = append(candidates, "contracts.json")

	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				if envPath != "" && path == envPath {
					return nil, fmt.Errorf("CUSTODIAN_E2E_CONTRACTS file %q not found: %w", path, err)
				}
				continue
			}
			return nil, fmt.Errorf("read contracts file %q: %w", path, err)
		}
		if err := json.Unmarshal(data, c); err != nil {
			return nil, fmt.Errorf("parse contracts file %q: %w", path, err)
		}
		break
	}

	if v := strings.TrimSpace(os.Getenv("CUSTODIAN_E2E_HEALTH_PATH")); v != "" {
		c.HealthPath = v
	}
	if v := strings.TrimSpace(os.Getenv("CUSTODIAN_E2E_READY_PATH")); v != "" {
		c.ReadyPath = v
	}
	if v := strings.TrimSpace(os.Getenv("CUSTODIAN_E2E_METRICS_PATH")); v != "" {
		c.MetricsPath = v
	}
	if v := strings.TrimSpace(os.Getenv("CUSTODIAN_E2E_GATEWAY_FORMAT")); v != "" {
		c.GatewayResponseFormat = v
	}
	if v := strings.TrimSpace(os.Getenv("CUSTODIAN_E2E_UPLOAD_METHOD")); v != "" {
		c.UploadCapabilityMethod = v
	}
	if v := strings.TrimSpace(os.Getenv("CUSTODIAN_E2E_UPLOAD_HEADER")); v != "" {
		c.UploadCapabilityHeader = v
	}

	return c, nil
}
