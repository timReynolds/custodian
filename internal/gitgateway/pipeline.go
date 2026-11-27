package gitgateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/audit"
	"github.com/timreynolds/custodian/internal/decisions"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/git/checkout"
	"github.com/timreynolds/custodian/internal/gitgateway/quarantine"
	"github.com/timreynolds/custodian/internal/inspection"
	"github.com/timreynolds/custodian/internal/observability"
	"github.com/timreynolds/custodian/internal/persistence"
	"github.com/timreynolds/custodian/internal/policy"
	"github.com/timreynolds/custodian/prompts"
)

const (
	maxStageAUnifiedDiffBytes    = 16 << 20
	maxStageBCommitMessagesBytes = 32 * 1024
	maxSidebandLineBytes         = 60000
	defaultArtifactTTL           = 720 * time.Hour
)

// PipelineConfig configures PipelineReceivePackHandler.
type PipelineConfig struct {
	Store                *persistence.Store
	SnapshotStore        domain.SnapshotStore
	QuarantineUnpacker   *quarantine.QuarantineUnpacker
	PolicyEngine         *policy.Engine
	PolicyDir            string
	InspectionConfig     inspection.Config
	InspectionRunner     inspection.Runner
	DecisionsService     *decisions.Service
	TokenBroker          *TokenBroker
	Upstream             UpstreamClient
	AuditService         *audit.Service
	GitBinary            string
	Limits               quarantine.Limits
	ArtifactRetentionTTL time.Duration
	RepoConcurrencyLimit int
	GlobalScanBudget     int
	Metrics              *observability.Metrics
	Logger               *slog.Logger
	Clock                func() time.Time
}

// PipelineReceivePackHandler executes the full M4b push gateway pipeline:
// ENFORCE_PR guard -> push_sessions -> upstream ExistingRefResolver + baseline fetch ->
// QuarantineUnpacker -> LFS pointer extraction & bundle upload -> Stage A -> Stage B ->
// Stage C -> push_approval_releases -> clean repack & upstream forward -> audit/metrics/sideband.
type PipelineReceivePackHandler struct {
	store        *persistence.Store
	snapStore    domain.SnapshotStore
	unpacker     *quarantine.QuarantineUnpacker
	policyEngine *policy.Engine
	policyDir    string
	inspRunner   inspection.Runner
	decSvc       *decisions.Service
	broker       *TokenBroker
	upstream     UpstreamClient
	auditSvc     *audit.Service
	gitBinary    string
	limits       quarantine.Limits
	artifactTTL  time.Duration
	repoLimit    int
	repoSemMu    sync.Mutex
	repoSems     map[string]chan struct{}
	scanBudget   chan struct{}
	metrics      *observability.Metrics
	logger       *slog.Logger
	nowFn        func() time.Time
}

// NewPipelineReceivePackHandler constructs a validated PipelineReceivePackHandler.
func NewPipelineReceivePackHandler(cfg PipelineConfig) (*PipelineReceivePackHandler, error) {
	if cfg.Store == nil {
		return nil, domain.BadRequest("INVALID_PIPELINE_CONFIG", "Store is required")
	}
	if cfg.SnapshotStore == nil {
		return nil, domain.BadRequest("INVALID_PIPELINE_CONFIG", "SnapshotStore is required")
	}
	if cfg.QuarantineUnpacker == nil {
		return nil, domain.BadRequest("INVALID_PIPELINE_CONFIG", "QuarantineUnpacker is required")
	}
	if cfg.PolicyEngine == nil {
		return nil, domain.BadRequest("INVALID_PIPELINE_CONFIG", "PolicyEngine is required")
	}
	if cfg.DecisionsService == nil {
		return nil, domain.BadRequest("INVALID_PIPELINE_CONFIG", "DecisionsService is required")
	}
	if cfg.Upstream == nil {
		return nil, domain.BadRequest("INVALID_PIPELINE_CONFIG", "UpstreamClient is required")
	}
	if cfg.AuditService == nil {
		return nil, domain.BadRequest("INVALID_PIPELINE_CONFIG", "AuditService is required")
	}

	runner := cfg.InspectionRunner
	if runner == nil {
		runner = inspection.NewRunner(cfg.InspectionConfig)
	}
	gitBin := strings.TrimSpace(cfg.GitBinary)
	if gitBin == "" {
		gitBin = "git"
	}
	ttl := cfg.ArtifactRetentionTTL
	if ttl <= 0 {
		ttl = defaultArtifactTTL
	}
	nowFn := cfg.Clock
	if nowFn == nil {
		nowFn = func() time.Time { return time.Now().UTC() }
	}
	var scanBudget chan struct{}
	if cfg.GlobalScanBudget > 0 {
		scanBudget = make(chan struct{}, cfg.GlobalScanBudget)
	}

	return &PipelineReceivePackHandler{
		store:        cfg.Store,
		snapStore:    cfg.SnapshotStore,
		unpacker:     cfg.QuarantineUnpacker,
		policyEngine: cfg.PolicyEngine,
		policyDir:    strings.TrimSpace(cfg.PolicyDir),
		inspRunner:   runner,
		decSvc:       cfg.DecisionsService,
		broker:       cfg.TokenBroker,
		upstream:     cfg.Upstream,
		auditSvc:     cfg.AuditService,
		gitBinary:    gitBin,
		limits:       cfg.Limits,
		artifactTTL:  ttl,
		repoLimit:    cfg.RepoConcurrencyLimit,
		repoSems:     make(map[string]chan struct{}),
		scanBudget:   scanBudget,
		metrics:      cfg.Metrics,
		logger:       cfg.Logger,
		nowFn:        nowFn,
	}, nil
}

// HandleReceivePack runs the complete push verification, assessment, policy, approval, and forwarding pipeline.
func (h *PipelineReceivePackHandler) HandleReceivePack(ctx context.Context, req ReceivePackRequest) (ReceivePackOutcome, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	startedAt := h.nowFn().UTC()

	sessionID := req.SessionID
	if sessionID == uuid.Nil {
		id, err := domain.NewID()
		if err != nil {
			return ReceivePackOutcome{}, err
		}
		sessionID = id
	}

	transport := req.Transport
	if !transport.IsValid() {
		transport = domain.PushTransportHTTPS
	}
	egressMode := req.Target.EgressMode
	if !egressMode.IsValid() {
		egressMode = domain.EgressModeEnforceBlock
	}
	delivery := req.Target.PassiveAuditDelivery
	if !delivery.IsValid() {
		delivery = domain.PassiveAuditDeliveryAsync
	}
	enforced := egressMode != domain.EgressModePassiveAudit

	extraSecrets := collectExtraSecrets(append(
		append([]string(nil), req.ExtraSecrets...),
		req.UpstreamToken,
		req.Caller.OIDCToken,
		req.Caller.DelegatedUpstreamToken,
	)...)

	finalStatus := domain.PushSessionStatusFailed
	finalEffect := domain.PolicyEffectDeny
	defer func() {
		h.metrics.ObservePushPhase(string(transport), string(egressMode), "total", h.nowFn().UTC().Sub(startedAt))
		h.metrics.RecordPushSession(string(transport), string(egressMode), string(finalEffect), string(finalStatus))
	}()

	releaseRepoSlot, err := h.acquireRepoSlot(ctx, req.Target.CanonicalDestination)
	if err != nil {
		return ReceivePackOutcome{
			SessionID:    sessionID,
			Status:       domain.PushSessionStatusFailed,
			Effect:       domain.PolicyEffectDeny,
			UnpackOK:     false,
			RefResults:   failAllRefs(req.RefUpdates, "gateway busy"),
			ErrorCode:    "GATEWAY_CONCURRENCY_TIMEOUT",
			ErrorMessage: "timed out waiting for repository push slot",
		}, err
	}
	defer releaseRepoSlot()

	var repoIDPtr *uuid.UUID
	if req.Target.Repository != nil && req.Target.Repository.ID != uuid.Nil {
		id := req.Target.Repository.ID
		repoIDPtr = &id
	}

	domRefs := make([]domain.PushRefUpdate, 0, len(req.RefUpdates))
	refNames := make([]string, 0, len(req.RefUpdates))
	for _, ru := range req.RefUpdates {
		domRefs = append(domRefs, domain.PushRefUpdate{
			RefName: ru.RefName,
			OldOID:  ru.OldOID,
			NewOID:  ru.NewOID,
		})
		refNames = append(refNames, ru.RefName)
	}

	// 1. Create initial push_sessions row strictly attributed to authenticated principal.
	_, err = h.store.CreatePushSession(ctx, persistence.CreatePushSessionParams{
		ID:                    sessionID,
		PrincipalID:           req.Caller.Principal.ID,
		RepositoryID:          repoIDPtr,
		Destination:           req.Target.CanonicalDestination,
		DestinationHost:       req.Target.Host,
		DestinationRegistered: req.Target.Registered,
		DestinationExternal:   req.Target.External,
		Transport:             transport,
		RefUpdates:            domRefs,
		EgressMode:            egressMode,
		PassiveAuditDelivery:  delivery,
		Enforced:              &enforced,
		Status:                domain.PushSessionStatusReceived,
		CreatedAt:             startedAt,
		UpdatedAt:             startedAt,
	})
	if err != nil {
		h.writeSidebandLines(req.SidebandWriter, extraSecrets, "ERROR: failed initializing push session")
		return ReceivePackOutcome{
			SessionID:     sessionID,
			Status:        domain.PushSessionStatusFailed,
			Effect:        domain.PolicyEffectDeny,
			UnpackOK:      false,
			UnpackMessage: "failed initializing push session",
			RefResults:    failAllRefs(req.RefUpdates, "push session initialization failed"),
			ErrorCode:     "PUSH_SESSION_INIT_FAILED",
			ErrorMessage:  "failed initializing push session",
			HTTPStatus:    http.StatusServiceUnavailable,
		}, nil
	}

	// 2. ENFORCE_PR rejects direct git push cleanly with 0 upstream bytes.
	if egressMode == domain.EgressModeEnforcePR {
		const msg = "direct git push is disabled in ENFORCE_PR mode; submit changes via the Custodian pull request workflow"
		finalStatus = domain.PushSessionStatusBlocked
		finalEffect = domain.PolicyEffectDeny
		_, _ = h.store.CompletePushSession(ctx, persistence.CompletePushSessionParams{
			ID:                sessionID,
			Status:            domain.PushSessionStatusBlocked,
			UpstreamForwarded: false,
			UpstreamBytesSent: 0,
			ErrorCode:         "ENFORCE_PR_DIRECT_PUSH_FORBIDDEN",
			ErrorMessage:      msg,
			UpdatedAt:         h.nowFn().UTC(),
			CompletedAt:       h.nowFn().UTC(),
		})
		h.emitPushAudit(ctx, nil, "push.blocked", req, sessionID, repoIDPtr, "", false, 0, 0, nil, nil, finalEffect, finalStatus, false, 0, "ENFORCE_PR_DIRECT_PUSH_FORBIDDEN")
		h.writeSidebandLines(req.SidebandWriter, extraSecrets, "ENFORCE_PR: "+msg)
		return ReceivePackOutcome{
			SessionID:         sessionID,
			Status:            domain.PushSessionStatusBlocked,
			Effect:            domain.PolicyEffectDeny,
			UpstreamForwarded: false,
			UpstreamBytesSent: 0,
			UnpackOK:          false,
			UnpackMessage:     msg,
			RefResults:        failAllRefs(req.RefUpdates, "ENFORCE_PR: direct push disabled"),
			ErrorCode:         "ENFORCE_PR_DIRECT_PUSH_FORBIDDEN",
			ErrorMessage:      msg,
			HTTPStatus:        0,
		}, nil
	}

	_ = h.updatePushSessionStatus(ctx, sessionID, domain.PushSessionStatusUnpacking)

	// 3. Query upstream refs (ExistingRefResolver) and fetch ephemeral baseline when needed.
	upstreamRefs, refErr := h.resolveUpstreamRefs(ctx, req)
	if refErr != nil {
		code, safeMsg := safeGatewayError(refErr, extraSecrets...)
		finalStatus = domain.PushSessionStatusFailed
		finalEffect = domain.PolicyEffectDeny
		_, _ = h.store.CompletePushSession(ctx, persistence.CompletePushSessionParams{
			ID:                sessionID,
			Status:            domain.PushSessionStatusFailed,
			UpstreamForwarded: false,
			UpstreamBytesSent: 0,
			ErrorCode:         code,
			ErrorMessage:      safeMsg,
			UpdatedAt:         h.nowFn().UTC(),
			CompletedAt:       h.nowFn().UTC(),
		})
		h.emitPushAudit(ctx, nil, "push.failed", req, sessionID, repoIDPtr, "", false, 0, 0, nil, nil, finalEffect, finalStatus, false, 0, code)
		h.writeSidebandLines(req.SidebandWriter, extraSecrets, "DENY: "+safeMsg)
		return ReceivePackOutcome{
			SessionID:     sessionID,
			Status:        domain.PushSessionStatusFailed,
			Effect:        domain.PolicyEffectDeny,
			UnpackOK:      false,
			UnpackMessage: safeMsg,
			RefResults:    failAllRefs(req.RefUpdates, safeMsg),
			ErrorCode:     code,
			ErrorMessage:  safeMsg,
			HTTPStatus:    0,
		}, nil
	}

	hasNonZeroNewOID := false
	for _, ru := range req.RefUpdates {
		if ru.NewOID != "" && ru.NewOID != quarantine.ZeroOID {
			hasNonZeroNewOID = true
			break
		}
	}

	var (
		stageAOrBInfraFailed bool
		infraErrCode         string
		infraReason          string
	)

	var (
		baselineDir  string
		baseErr      error
		packSpool    *os.File
		packSpoolLen int64
	)
	if len(upstreamRefs) > 0 && hasNonZeroNewOID {
		baselineDir, baseErr = h.fetchEphemeralBaseline(ctx, req, upstreamRefs, &extraSecrets)
		if baseErr != nil {
			code, safeMsg := safeGatewayError(baseErr, extraSecrets...)
			if req.Target.Repository != nil && egressMode != domain.EgressModePassiveAudit {
				finalStatus = domain.PushSessionStatusFailed
				finalEffect = domain.PolicyEffectDeny
				_, _ = h.store.CompletePushSession(ctx, persistence.CompletePushSessionParams{
					ID:                sessionID,
					Status:            domain.PushSessionStatusFailed,
					UpstreamForwarded: false,
					UpstreamBytesSent: 0,
					ErrorCode:         code,
					ErrorMessage:      safeMsg,
					UpdatedAt:         h.nowFn().UTC(),
					CompletedAt:       h.nowFn().UTC(),
				})
				h.emitPushAudit(ctx, nil, "push.failed", req, sessionID, repoIDPtr, "", false, 0, 0, nil, nil, finalEffect, finalStatus, false, 0, code)
				h.writeSidebandLines(req.SidebandWriter, extraSecrets, "ERROR: "+safeMsg)
				return ReceivePackOutcome{
					SessionID:     sessionID,
					Status:        domain.PushSessionStatusFailed,
					Effect:        domain.PolicyEffectDeny,
					UnpackOK:      false,
					UnpackMessage: safeMsg,
					RefResults:    failAllRefs(req.RefUpdates, safeMsg),
					ErrorCode:     code,
					ErrorMessage:  safeMsg,
					HTTPStatus:    0,
				}, nil
			}
			if req.Target.Repository != nil {
				stageAOrBInfraFailed = true
				infraErrCode = code
				infraReason = safeMsg
			}
			baselineDir = ""
		}
		if baselineDir != "" {
			defer func(dir string) { _ = os.RemoveAll(dir) }(baselineDir)
		}
	}

	packReaderForUnpack := req.PackReader
	if egressMode == domain.EgressModePassiveAudit && baseErr != nil && hasNonZeroNewOID && req.PackReader != nil {
		maxSpool := h.limits.MaxPackBytes
		if maxSpool <= 0 {
			maxSpool = 64 << 20
		}
		spFile, spLen, spErr := spoolPassivePackReader(req.PackReader, maxSpool)
		if spErr != nil {
			code, safeMsg := safeGatewayError(spErr, extraSecrets...)
			finalStatus = domain.PushSessionStatusFailed
			finalEffect = domain.PolicyEffectDeny
			_, _ = h.store.CompletePushSession(ctx, persistence.CompletePushSessionParams{
				ID:                sessionID,
				Status:            domain.PushSessionStatusFailed,
				UpstreamForwarded: false,
				UpstreamBytesSent: 0,
				ErrorCode:         code,
				ErrorMessage:      safeMsg,
				UpdatedAt:         h.nowFn().UTC(),
				CompletedAt:       h.nowFn().UTC(),
			})
			h.emitPushAudit(ctx, nil, "push.failed", req, sessionID, repoIDPtr, "", false, 0, 0, nil, nil, finalEffect, finalStatus, false, 0, code)
			h.writeSidebandLines(req.SidebandWriter, extraSecrets, "ERROR: "+safeMsg)
			if errors.Is(spErr, errStreamLimitExceeded) {
				return ReceivePackOutcome{}, spErr
			}
			return ReceivePackOutcome{
				SessionID:     sessionID,
				Status:        domain.PushSessionStatusFailed,
				Effect:        domain.PolicyEffectDeny,
				UnpackOK:      false,
				UnpackMessage: safeMsg,
				RefResults:    failAllRefs(req.RefUpdates, safeMsg),
				ErrorCode:     code,
				ErrorMessage:  safeMsg,
				HTTPStatus:    0,
			}, nil
		}
		packSpool = spFile
		packSpoolLen = spLen
		defer func(f *os.File) {
			name := f.Name()
			_ = f.Close()
			_ = os.Remove(name)
		}(packSpool)
		packReaderForUnpack = packSpool
	}

	// 4. Quarantine Unpack (with SnapshotStore: nil so we can update LFS manifest before storing).
	unpackStart := h.nowFn().UTC()
	unpackRes, unpackErr := h.unpacker.Unpack(ctx, quarantine.UnpackRequest{
		PushSessionID:       sessionID,
		PackReader:          packReaderForUnpack,
		RefUpdates:          req.RefUpdates,
		BaselineRepoDir:     baselineDir,
		ExistingRefResolver: &upstreamRefResolver{refs: upstreamRefs},
		SnapshotStore:       nil,
		Limits:              h.limits,
	})
	h.metrics.ObservePushPhase(string(transport), string(egressMode), "unpack", h.nowFn().UTC().Sub(unpackStart))
	if unpackErr != nil {
		if egressMode == domain.EgressModePassiveAudit && baseErr != nil && packSpool != nil {
			if _, seekErr := packSpool.Seek(0, io.SeekStart); seekErr == nil {
				out, fwdErr := h.forwardPassiveAuditRawPack(ctx, req, sessionID, repoIDPtr, transport, egressMode, delivery, packSpool, packSpoolLen, infraErrCode, infraReason, extraSecrets)
				finalStatus = out.Status
				finalEffect = out.Effect
				return out, fwdErr
			}
		}
		code, safeMsg := safeGatewayError(unpackErr, extraSecrets...)
		status := domain.PushSessionStatusQuarantined
		if errors.Is(unpackErr, domain.ErrInternal) || errors.Is(unpackErr, domain.ErrUnavailable) {
			status = domain.PushSessionStatusFailed
		}
		if errors.Is(unpackErr, errStreamLimitExceeded) {
			status = domain.PushSessionStatusBlocked
			code = "PACK_TOO_LARGE"
			safeMsg = "pack stream exceeds max_pack_bytes"
		}
		finalStatus = status
		finalEffect = domain.PolicyEffectQuarantine
		_, _ = h.store.CompletePushSession(ctx, persistence.CompletePushSessionParams{
			ID:                sessionID,
			Status:            status,
			UpstreamForwarded: false,
			UpstreamBytesSent: 0,
			ErrorCode:         code,
			ErrorMessage:      safeMsg,
			UpdatedAt:         h.nowFn().UTC(),
			CompletedAt:       h.nowFn().UTC(),
		})
		h.emitPushAudit(ctx, nil, "push.quarantined", req, sessionID, repoIDPtr, "", false, 0, 0, nil, nil, finalEffect, finalStatus, false, 0, code)
		h.writeSidebandLines(req.SidebandWriter, extraSecrets, "QUARANTINE: "+safeMsg)
		if errors.Is(unpackErr, errStreamLimitExceeded) {
			return ReceivePackOutcome{}, unpackErr
		}
		return ReceivePackOutcome{
			SessionID:     sessionID,
			Status:        status,
			Effect:        domain.PolicyEffectQuarantine,
			UnpackOK:      false,
			UnpackMessage: safeMsg,
			RefResults:    failAllRefs(req.RefUpdates, safeMsg),
			ErrorCode:     code,
			ErrorMessage:  safeMsg,
			HTTPStatus:    0,
		}, nil
	}
	defer func() { _ = unpackRes.Close() }()

	// 5. Extract Git LFS v1 pointers, rebuild bundle if LFS objects present, upload to SnapshotStore.
	lfsObjects, lfsErr := extractLFSPointers(ctx, h.gitBinary, unpackRes)
	if lfsErr != nil {
		code, safeMsg := safeGatewayError(lfsErr, extraSecrets...)
		finalStatus = domain.PushSessionStatusQuarantined
		finalEffect = domain.PolicyEffectQuarantine
		_, _ = h.store.CompletePushSession(ctx, persistence.CompletePushSessionParams{
			ID:                sessionID,
			Status:            domain.PushSessionStatusQuarantined,
			UpstreamForwarded: false,
			UpstreamBytesSent: 0,
			ErrorCode:         code,
			ErrorMessage:      safeMsg,
			UpdatedAt:         h.nowFn().UTC(),
			CompletedAt:       h.nowFn().UTC(),
		})
		h.emitPushAudit(ctx, nil, "push.quarantined", req, sessionID, repoIDPtr, unpackRes.PushManifestDigest, false, 0, 0, nil, nil, finalEffect, finalStatus, false, 0, code)
		h.writeSidebandLines(req.SidebandWriter, extraSecrets, "QUARANTINE: "+safeMsg)
		return ReceivePackOutcome{
			SessionID:          sessionID,
			Status:             domain.PushSessionStatusQuarantined,
			Effect:             domain.PolicyEffectQuarantine,
			UnpackOK:           false,
			UnpackMessage:      safeMsg,
			RefResults:         failAllRefs(req.RefUpdates, safeMsg),
			PushManifestDigest: unpackRes.PushManifestDigest,
			ErrorCode:          code,
			ErrorMessage:       safeMsg,
			HTTPStatus:         0,
		}, nil
	}

	hasLFS := len(lfsObjects) > 0
	var lfsCount, lfsTotalBytes int64
	lfsSizeOverflow := false
	for _, o := range lfsObjects {
		if o.Size < 0 || o.Size > math.MaxInt64-lfsTotalBytes {
			lfsSizeOverflow = true
			break
		}
		lfsCount++
		lfsTotalBytes += o.Size
	}
	if lfsSizeOverflow {
		const code = "LFS_SIZE_OVERFLOW"
		const safeMsg = "cumulative LFS object size exceeds int64 limit"
		if egressMode != domain.EgressModePassiveAudit {
			finalStatus = domain.PushSessionStatusQuarantined
			finalEffect = domain.PolicyEffectQuarantine
			_, _ = h.store.CompletePushSession(ctx, persistence.CompletePushSessionParams{
				ID:                sessionID,
				Status:            domain.PushSessionStatusQuarantined,
				UpstreamForwarded: false,
				UpstreamBytesSent: 0,
				ErrorCode:         code,
				ErrorMessage:      safeMsg,
				UpdatedAt:         h.nowFn().UTC(),
				CompletedAt:       h.nowFn().UTC(),
			})
			h.emitPushAudit(ctx, nil, "push.quarantined", req, sessionID, repoIDPtr, unpackRes.PushManifestDigest, hasLFS, int64(len(lfsObjects)), 0, nil, nil, finalEffect, finalStatus, false, 0, code)
			h.writeSidebandLines(req.SidebandWriter, extraSecrets, "QUARANTINE: "+safeMsg)
			return ReceivePackOutcome{
				SessionID:          sessionID,
				Status:             domain.PushSessionStatusQuarantined,
				Effect:             domain.PolicyEffectQuarantine,
				UnpackOK:           false,
				UnpackMessage:      safeMsg,
				RefResults:         failAllRefs(req.RefUpdates, safeMsg),
				PushManifestDigest: unpackRes.PushManifestDigest,
				ErrorCode:          code,
				ErrorMessage:       safeMsg,
				HTTPStatus:         0,
			}, nil
		}
		lfsCount = int64(len(lfsObjects))
		lfsTotalBytes = math.MaxInt64
		stageAOrBInfraFailed = true
		if infraErrCode == "" {
			infraErrCode = code
			infraReason = safeMsg
		}
	}

	bundleArt, err := finalizeAndUploadPushBundle(ctx, unpackRes, lfsObjects, h.snapStore)
	if err != nil {
		code, safeMsg := safeGatewayError(err, extraSecrets...)
		if egressMode != domain.EgressModePassiveAudit {
			finalStatus = domain.PushSessionStatusFailed
			finalEffect = domain.PolicyEffectDeny
			_, _ = h.store.CompletePushSession(ctx, persistence.CompletePushSessionParams{
				ID:                sessionID,
				Status:            domain.PushSessionStatusFailed,
				UpstreamForwarded: false,
				UpstreamBytesSent: 0,
				ErrorCode:         code,
				ErrorMessage:      safeMsg,
				UpdatedAt:         h.nowFn().UTC(),
				CompletedAt:       h.nowFn().UTC(),
			})
			h.emitPushAudit(ctx, nil, "push.failed", req, sessionID, repoIDPtr, unpackRes.PushManifestDigest, hasLFS, lfsCount, lfsTotalBytes, nil, nil, finalEffect, finalStatus, false, 0, code)
			h.writeSidebandLines(req.SidebandWriter, extraSecrets, "ERROR: "+safeMsg)
			return ReceivePackOutcome{
				SessionID:          sessionID,
				Status:             domain.PushSessionStatusFailed,
				Effect:             domain.PolicyEffectDeny,
				UnpackOK:           false,
				UnpackMessage:      safeMsg,
				RefResults:         failAllRefs(req.RefUpdates, safeMsg),
				PushManifestDigest: unpackRes.PushManifestDigest,
				ErrorCode:          code,
				ErrorMessage:       safeMsg,
				HTTPStatus:         0,
			}, nil
		}
		bundleArt = domain.Artifact{}
		stageAOrBInfraFailed = true
		if infraErrCode == "" {
			infraErrCode = code
			infraReason = safeMsg
		}
	}

	manifestDigest := unpackRes.PushManifestDigest
	expiresAt := h.nowFn().UTC().Add(h.artifactTTL).Truncate(time.Microsecond)
	lfsJSON, err := json.Marshal(nonNilLFSObjects(lfsObjects))
	if err != nil {
		return ReceivePackOutcome{}, err
	}
	canonLFSJSON, err := domain.CanonicalJSONBytes(lfsJSON)
	if err != nil {
		return ReceivePackOutcome{}, err
	}

	var artRow persistence.ArtifactRow
	if err := h.store.WithTx(ctx, func(tx *persistence.Tx) error {
		var txErr error
		var bundleArtIDPtr *uuid.UUID
		if bundleArt.ID != uuid.Nil {
			artRow, txErr = tx.RegisterArtifact(ctx, persistence.RegisterArtifactParams{
				ID:                bundleArt.ID,
				Kind:              domain.ArtifactKindGitPushBundle,
				SHA256:            bundleArt.SHA256,
				StorageKey:        bundleArt.StorageKey,
				StorageGeneration: bundleArt.StorageGeneration,
				SizeBytes:         bundleArt.SizeBytes,
				Format:            "application/gzip",
				UploadedBy:        &req.Caller.Principal.ID,
				ExpiresAt:         &expiresAt,
				CreatedAt:         h.nowFn().UTC(),
			})
			if txErr != nil {
				return txErr
			}
			bundleArtIDPtr = &artRow.ID
		}
		if _, txErr = tx.UpdatePushSessionUnpack(ctx, persistence.UpdatePushSessionUnpackParams{
			ID:                 sessionID,
			PushManifestDigest: manifestDigest,
			BundleArtifactID:   bundleArtIDPtr,
			RefUpdates:         domRefs,
			Status:             domain.PushSessionStatusQuarantined,
			UpdatedAt:          h.nowFn().UTC(),
		}); txErr != nil {
			return txErr
		}
		_, txErr = tx.Tx().Exec(ctx, `
			UPDATE push_sessions
			SET has_lfs = $2,
			    lfs_objects = $3::jsonb,
			    lfs_object_count = $4,
			    lfs_total_bytes = $5
			WHERE id = $1
		`, sessionID, hasLFS, canonLFSJSON, lfsCount, lfsTotalBytes)
		return persistence.MapError(txErr)
	}); err != nil {
		code, safeMsg := safeGatewayError(err, extraSecrets...)
		if egressMode != domain.EgressModePassiveAudit {
			finalStatus = domain.PushSessionStatusFailed
			finalEffect = domain.PolicyEffectDeny
			_, _ = h.store.CompletePushSession(ctx, persistence.CompletePushSessionParams{
				ID:                sessionID,
				Status:            domain.PushSessionStatusFailed,
				UpstreamForwarded: false,
				UpstreamBytesSent: 0,
				ErrorCode:         code,
				ErrorMessage:      safeMsg,
				UpdatedAt:         h.nowFn().UTC(),
				CompletedAt:       h.nowFn().UTC(),
			})
			h.writeSidebandLines(req.SidebandWriter, extraSecrets, "ERROR: "+safeMsg)
			return ReceivePackOutcome{
				SessionID:          sessionID,
				Status:             domain.PushSessionStatusFailed,
				Effect:             domain.PolicyEffectDeny,
				UnpackOK:           false,
				UnpackMessage:      safeMsg,
				RefResults:         failAllRefs(req.RefUpdates, safeMsg),
				PushManifestDigest: manifestDigest,
				ErrorCode:          code,
				ErrorMessage:       safeMsg,
				HTTPStatus:         0,
			}, nil
		}
		artRow = persistence.ArtifactRow{}
		stageAOrBInfraFailed = true
		if infraErrCode == "" {
			infraErrCode = code
			infraReason = safeMsg
		}
	}

	// 6. Load active ORG + REPO PUSH_EGRESS policy bundles and transition to INSPECTING.
	_ = h.updatePushSessionStatus(ctx, sessionID, domain.PushSessionStatusInspecting)

	orgBundles, repoBundles, bundleErr := resolveActivePushPolicyBundles(ctx, h.store, h.policyEngine, h.policyDir, repoIDPtr, h.nowFn().UTC())
	var bundleSafeMsg string
	if bundleErr != nil {
		code, safeMsg := safeGatewayError(bundleErr, extraSecrets...)
		if egressMode != domain.EgressModePassiveAudit {
			finalStatus = domain.PushSessionStatusFailed
			finalEffect = domain.PolicyEffectDeny
			_, _ = h.store.CompletePushSession(ctx, persistence.CompletePushSessionParams{
				ID:                sessionID,
				Status:            domain.PushSessionStatusFailed,
				UpstreamForwarded: false,
				UpstreamBytesSent: 0,
				ErrorCode:         code,
				ErrorMessage:      safeMsg,
				UpdatedAt:         h.nowFn().UTC(),
				CompletedAt:       h.nowFn().UTC(),
			})
			h.emitPushAudit(ctx, nil, "push.failed", req, sessionID, repoIDPtr, manifestDigest, hasLFS, lfsCount, lfsTotalBytes, nil, nil, finalEffect, finalStatus, false, 0, code)
			h.writeSidebandLines(req.SidebandWriter, extraSecrets, "DENY: "+safeMsg)
			return ReceivePackOutcome{
				SessionID:          sessionID,
				Status:             domain.PushSessionStatusFailed,
				Effect:             domain.PolicyEffectDeny,
				UnpackOK:           true,
				RefResults:         failAllRefs(req.RefUpdates, safeMsg),
				PushManifestDigest: manifestDigest,
				ErrorCode:          code,
				ErrorMessage:       safeMsg,
				HTTPStatus:         0,
			}, nil
		}
		stageAOrBInfraFailed = true
		bundleSafeMsg = safeMsg
		if infraErrCode == "" {
			infraErrCode = code
			infraReason = safeMsg
		}
		orgBundles = nil
		repoBundles = nil
		h.emitPushAudit(ctx, nil, "push.policy_bundle_invalid", req, sessionID, repoIDPtr, manifestDigest, hasLFS, lfsCount, lfsTotalBytes, nil, nil, domain.PolicyEffectDeny, domain.PushSessionStatusObservedWouldBlock, false, 0, code)
	}

	inspPolicyCfg := composePushInspectionConfig(orgBundles, repoBundles)
	effClass := domain.ClassificationInternal
	var allowedRoutes []string
	if req.Target.Repository != nil {
		if req.Target.Repository.Classification.IsValid() {
			effClass = req.Target.Repository.Classification
		}
		if req.Target.AllowedModelRoutes != nil {
			allowedRoutes = append([]string(nil), req.Target.AllowedModelRoutes...)
		} else if h.store != nil && req.Target.Repository.ID != uuid.Nil {
			if repoRow, repoErr := h.store.GetRepositoryByID(ctx, req.Target.Repository.ID); repoErr == nil {
				allowedRoutes = append([]string(nil), repoRow.AllowedModelRoutes...)
			}
		}
	}

	unifiedDiff := assembleBoundedUnifiedDiff(unpackRes.WorkspaceDir, maxStageAUnifiedDiffBytes)

	inspectTargetDir := unpackRes.WorkspaceDir
	if len(lfsObjects) > 0 {
		if lfsDir, cleanupLFSDir, lfsDirErr := prepareLFSInspectionDir(unpackRes.WorkspaceDir); lfsDirErr == nil {
			inspectTargetDir = lfsDir
			defer cleanupLFSDir()
		}
	}

	// 7. Stage A Inspection.
	inMemArtifactID := artRow.ID
	if inMemArtifactID == uuid.Nil {
		inMemArtifactID = sessionID
	}
	inspectStart := h.nowFn().UTC()
	var (
		report     inspection.Report
		inspectErr error
	)
	func() {
		releaseScan, scanBudgetErr := h.acquireScanBudget(ctx)
		if scanBudgetErr != nil {
			inspectErr = scanBudgetErr
			return
		}
		defer releaseScan()
		report, inspectErr = h.inspRunner.Inspect(ctx, inspection.Request{
			ProposalID:        uuid.Nil,
			PushSessionID:     &sessionID,
			ArtifactID:        inMemArtifactID,
			TargetDir:         inspectTargetDir,
			Classification:    effClass,
			Stage:             inspection.StagePushEgress,
			ChangedPaths:      unpackRes.ChangedPaths,
			MandatoryScanners: inspPolicyCfg.Mandatory,
			UnifiedDiff:       unifiedDiff,
			ExtraSecrets:      extraSecrets,
		})
	}()
	h.metrics.ObservePushPhase(string(transport), string(egressMode), "inspect", h.nowFn().UTC().Sub(inspectStart))

	if inspectErr != nil {
		stageAOrBInfraFailed = true
		report = inspection.Report{
			PushSessionID: &sessionID,
			ArtifactID:    inMemArtifactID,
			Summary: inspection.InspectionSummary{
				MandatoryScannersComplete: false,
				ScanComplete:              false,
				CountsByCategory:          map[string]int{},
				CountsBySeverity:          map[string]int{},
				CountsByScanner:           map[string]int{},
				EvidenceIDs:               []string{},
				FailedScanners:            []string{"inspection_runner"},
				IncompleteScanners:        []string{},
			},
		}
	} else {
		report.Summary = enforcePushMandatoryScanners(report.Summary, report.ScanRuns, inspPolicyCfg.Mandatory)
		if artRow.ID != uuid.Nil {
			if persistErr := h.persistStageAReport(ctx, sessionID, artRow.ID, report); persistErr != nil {
				code, safeMsg := safeGatewayError(persistErr, extraSecrets...)
				if egressMode == domain.EgressModeEnforceBlock {
					finalStatus = domain.PushSessionStatusQuarantined
					finalEffect = domain.PolicyEffectQuarantine
					_, _ = h.store.CompletePushSession(ctx, persistence.CompletePushSessionParams{
						ID:                sessionID,
						Status:            domain.PushSessionStatusQuarantined,
						UpstreamForwarded: false,
						UpstreamBytesSent: 0,
						ErrorCode:         code,
						ErrorMessage:      safeMsg,
						UpdatedAt:         h.nowFn().UTC(),
						CompletedAt:       h.nowFn().UTC(),
					})
					h.emitPushAudit(ctx, nil, "push.quarantined", req, sessionID, repoIDPtr, manifestDigest, hasLFS, lfsCount, lfsTotalBytes, nil, nil, finalEffect, finalStatus, false, 0, code)
					h.writeSidebandLines(req.SidebandWriter, extraSecrets, "QUARANTINE: "+safeMsg)
					return ReceivePackOutcome{
						SessionID:          sessionID,
						Status:             domain.PushSessionStatusQuarantined,
						Effect:             domain.PolicyEffectQuarantine,
						UnpackOK:           true,
						RefResults:         failAllRefs(req.RefUpdates, safeMsg),
						PushManifestDigest: manifestDigest,
						ErrorCode:          code,
						ErrorMessage:       safeMsg,
						HTTPStatus:         0,
					}, nil
				}
				stageAOrBInfraFailed = true
			}
		}
	}

	// 8. Stage B Conditional IP Provenance Assessment.
	_ = h.updatePushSessionStatus(ctx, sessionID, domain.PushSessionStatusEvaluating)

	assessStart := h.nowFn().UTC()
	var triggers []string
	if inspPolicyCfg.DecisionModel != nil {
		triggers = inspPolicyCfg.DecisionModel.Trigger
	}
	shouldRunStageB := shouldTriggerStageB(triggers, report.Summary, req.Target)

	modelRoute := resolvePushModelRoute(allowedRoutes, orgBundles, repoBundles, inspPolicyCfg)
	var assessment domain.ModelAssessment
	if !shouldRunStageB {
		assessment, err = decisions.BuildNotRequiredAssessment(decisions.NotRequiredAssessmentInput{
			ProposalID:     uuid.Nil,
			PushSessionID:  &sessionID,
			ArtifactID:     inMemArtifactID,
			AssessmentType: prompts.AssessmentTypeIPProvenance,
			InputDigest:    manifestDigest,
			Reason:         "Stage B IP provenance assessment not required for clean push",
			CreatedAt:      h.nowFn().UTC(),
		})
		if err != nil {
			stageAOrBInfraFailed = true
			assessment = buildFallbackFailedAssessment(sessionID, inMemArtifactID, modelRoute, manifestDigest, h.nowFn().UTC())
		}
	} else {
		repoForAssess := domain.Repository{
			FullName:       req.Target.OwnerRepo,
			Classification: effClass,
			Enabled:        true,
		}
		assessAllowedRoutes := []string{modelRoute}
		if req.Target.Repository != nil {
			repoForAssess = *req.Target.Repository
			assessAllowedRoutes = append([]string(nil), allowedRoutes...)
		}

		extraRedactor := inspection.NewRedactor(extraSecrets...)
		scrubForStageB := func(s string) string {
			return extraRedactor.ScrubString(report.ScrubText(s))
		}
		scrubbedPaths := make([]string, 0, len(unpackRes.ChangedPaths))
		for _, p := range unpackRes.ChangedPaths {
			scrubbedPaths = append(scrubbedPaths, scrubForStageB(p))
		}
		maxStageBTotalBytes := int64(decisions.DefaultMaxDiffBytes)
		if maxStageAUnifiedDiffBytes < maxStageBTotalBytes {
			maxStageBTotalBytes = maxStageAUnifiedDiffBytes
		}
		scrubbedDiff := assembleStageBContextDiff(unpackRes.Commits, unifiedDiff, maxStageBTotalBytes, scrubForStageB)

		baseCommit := ""
		targetRef := ""
		if len(req.RefUpdates) > 0 {
			baseCommit = req.RefUpdates[0].OldOID
			targetRef = scrubForStageB(req.RefUpdates[0].RefName)
		}

		assessed, assessErr := h.decSvc.Assess(ctx, decisions.AssessRequest{
			ProposalID:         sessionID,
			ArtifactID:         inMemArtifactID,
			Repository:         repoForAssess,
			AllowedModelRoutes: assessAllowedRoutes,
			ModelRoute:         modelRoute,
			AssessmentType:     prompts.AssessmentTypeIPProvenance,
			BaseCommit:         baseCommit,
			TargetRef:          targetRef,
			ChangedPaths:       scrubbedPaths,
			ScanRuns:           report.ScanRuns,
			Findings:           report.Findings,
			CanonicalDiff:      scrubbedDiff,
		})
		if assessErr != nil {
			stageAOrBInfraFailed = true
		}
		if assessed.ID != uuid.Nil {
			assessed.ProposalID = uuid.Nil
			sid := sessionID
			assessed.PushSessionID = &sid
			assessment = assessed
		} else {
			assessment = buildFallbackFailedAssessment(sessionID, inMemArtifactID, modelRoute, manifestDigest, h.nowFn().UTC())
			stageAOrBInfraFailed = true
		}
	}
	h.metrics.ObservePushPhase(string(transport), string(egressMode), "assess", h.nowFn().UTC().Sub(assessStart))

	if artRow.ID != uuid.Nil {
		if _, persistErr := h.persistModelAssessment(ctx, assessment); persistErr != nil {
			code, safeMsg := safeGatewayError(persistErr, extraSecrets...)
			if egressMode == domain.EgressModeEnforceBlock {
				finalStatus = domain.PushSessionStatusQuarantined
				finalEffect = domain.PolicyEffectQuarantine
				_, _ = h.store.CompletePushSession(ctx, persistence.CompletePushSessionParams{
					ID:                sessionID,
					Status:            domain.PushSessionStatusQuarantined,
					UpstreamForwarded: false,
					UpstreamBytesSent: 0,
					ErrorCode:         code,
					ErrorMessage:      safeMsg,
					UpdatedAt:         h.nowFn().UTC(),
					CompletedAt:       h.nowFn().UTC(),
				})
				h.emitPushAudit(ctx, nil, "push.quarantined", req, sessionID, repoIDPtr, manifestDigest, hasLFS, lfsCount, lfsTotalBytes, nil, nil, finalEffect, finalStatus, false, 0, code)
				h.writeSidebandLines(req.SidebandWriter, extraSecrets, "QUARANTINE: "+safeMsg)
				return ReceivePackOutcome{
					SessionID:          sessionID,
					Status:             domain.PushSessionStatusQuarantined,
					Effect:             domain.PolicyEffectQuarantine,
					UpstreamForwarded:  false,
					UpstreamBytesSent:  0,
					UnpackOK:           true,
					RefResults:         failAllRefs(req.RefUpdates, safeMsg),
					PushManifestDigest: manifestDigest,
					ErrorCode:          code,
					ErrorMessage:       safeMsg,
					HTTPStatus:         0,
				}, nil
			}
			stageAOrBInfraFailed = true
		}
	}

	// 9. Check active push_approval_releases and evaluate Stage C PUSH_EGRESS CEL.
	now := h.nowFn().UTC()
	approvalUsable := false
	relRow, relErr := h.store.GetActivePushApprovalRelease(ctx, req.Caller.Principal.ID, req.Target.CanonicalDestination, manifestDigest, now)
	if relErr == nil {
		if useErr := relRow.ToDomain().IsUsableFor(now, req.Caller.Principal.ID, req.Target.Host, req.Target.OwnerRepo, manifestDigest); useErr == nil {
			approvalUsable = true
		} else {
			h.metrics.IncPushApprovalRelease("rejected")
		}
	}

	policyInput := buildPushPolicyInput(
		req,
		unpackRes,
		report.Summary,
		assessment,
		effClass,
		hasLFS,
		lfsCount,
		lfsTotalBytes,
		refNames,
		approvalUsable,
		manifestDigest,
	)

	policyStart := h.nowFn().UTC()
	var (
		evalOutcome composedPushEvalOutcome
		evalErr     error
	)
	if bundleErr != nil {
		evalOutcome = composedPushEvalOutcome{
			result: policy.EvalResult{
				Effect: domain.PolicyEffectDeny,
				Reasons: []domain.PolicyReason{{
					RuleID:  "policy.bundle_invalid",
					Effect:  domain.PolicyEffectDeny,
					Stage:   policy.StagePushEgress,
					Message: bundleSafeMsg,
				}},
				InputDigest: domain.SHA256Hex([]byte(manifestDigest)),
				HadError:    true,
			},
		}
	} else {
		evalOutcome, evalErr = evaluateComposedPushBundles(ctx, h.policyEngine, orgBundles, repoBundles, policy.StagePushEgress, policyInput)
	}
	h.metrics.ObservePushPhase(string(transport), string(egressMode), "policy", h.nowFn().UTC().Sub(policyStart))

	if evalErr != nil || evalOutcome.result.HadError {
		stageAOrBInfraFailed = true
		if evalErr != nil {
			evalOutcome.result = policy.EvalResult{
				Effect: domain.PolicyEffectDeny,
				Reasons: []domain.PolicyReason{{
					RuleID:  "policy.eval_error",
					Effect:  domain.PolicyEffectDeny,
					Stage:   policy.StagePushEgress,
					Message: "policy evaluation failed",
				}},
				HadError: true,
			}
			if len(orgBundles) > 0 {
				evalOutcome.primaryBundleID = orgBundles[0].row.ID
				id := orgBundles[0].row.ID
				evalOutcome.orgBundleID = &id
			} else if len(repoBundles) > 0 {
				evalOutcome.primaryBundleID = repoBundles[0].row.ID
				id := repoBundles[0].row.ID
				evalOutcome.repoBundleID = &id
			}
			evalOutcome.result.InputDigest = domain.SHA256Hex([]byte(manifestDigest))
		}
		if egressMode == domain.EgressModeEnforceBlock {
			evalOutcome.result.Effect = domain.PolicyEffectDeny
		}
	}

	effectiveEffect := evalOutcome.result.Effect
	initialStatus := statusForPolicyEffect(egressMode, effectiveEffect, stageAOrBInfraFailed)
	var pdRow persistence.PolicyDecisionRow
	var pdIDPtr *uuid.UUID
	if evalOutcome.primaryBundleID != uuid.Nil {
		if err := h.store.WithTx(ctx, func(tx *persistence.Tx) error {
			var txErr error
			pdRow, txErr = tx.CreatePolicyDecision(ctx, persistence.CreatePolicyDecisionParams{
				ProposalID:     uuid.Nil,
				PushSessionID:  &sessionID,
				PolicyBundleID: evalOutcome.primaryBundleID,
				OrgBundleID:    evalOutcome.orgBundleID,
				RepoBundleID:   evalOutcome.repoBundleID,
				Stage:          policy.StagePushEgress,
				Enforced:       &enforced,
				InputDigest:    evalOutcome.result.InputDigest,
				Effect:         effectiveEffect,
				Reasons:        evalOutcome.result.Reasons,
				Obligations:    evalOutcome.result.Obligations,
				CreatedAt:      h.nowFn().UTC(),
			})
			if txErr != nil {
				return txErr
			}
			_, txErr = tx.ApplyPushSessionPolicyDecision(ctx, persistence.ApplyPushSessionPolicyDecisionParams{
				ID:               sessionID,
				PolicyDecisionID: pdRow.ID,
				Verdict:          effectiveEffect,
				Status:           initialStatus,
				UpdatedAt:        h.nowFn().UTC(),
			})
			return txErr
		}); err != nil {
			code, safeMsg := safeGatewayError(err, extraSecrets...)
			if egressMode != domain.EgressModePassiveAudit {
				finalStatus = domain.PushSessionStatusFailed
				finalEffect = domain.PolicyEffectDeny
				_, _ = h.store.CompletePushSession(ctx, persistence.CompletePushSessionParams{
					ID:                sessionID,
					Status:            domain.PushSessionStatusFailed,
					UpstreamForwarded: false,
					UpstreamBytesSent: 0,
					ErrorCode:         code,
					ErrorMessage:      safeMsg,
					UpdatedAt:         h.nowFn().UTC(),
					CompletedAt:       h.nowFn().UTC(),
				})
				h.writeSidebandLines(req.SidebandWriter, extraSecrets, "DENY: "+safeMsg)
				return ReceivePackOutcome{
					SessionID:          sessionID,
					Status:             domain.PushSessionStatusFailed,
					Effect:             domain.PolicyEffectDeny,
					UnpackOK:           true,
					RefResults:         failAllRefs(req.RefUpdates, safeMsg),
					PushManifestDigest: manifestDigest,
					ErrorCode:          code,
					ErrorMessage:       safeMsg,
					HTTPStatus:         0,
				}, nil
			}
			pdRow = persistence.PolicyDecisionRow{}
			stageAOrBInfraFailed = true
			if infraErrCode == "" {
				infraErrCode = code
				infraReason = safeMsg
			}
		}
		if pdRow.ID != uuid.Nil {
			id := pdRow.ID
			pdIDPtr = &id
		}
	} else if egressMode != domain.EgressModePassiveAudit {
		const code = "INVALID_POLICY_BUNDLE"
		const safeMsg = "no active policy bundle resolved"
		finalStatus = domain.PushSessionStatusFailed
		finalEffect = domain.PolicyEffectDeny
		_, _ = h.store.CompletePushSession(ctx, persistence.CompletePushSessionParams{
			ID:                sessionID,
			Status:            domain.PushSessionStatusFailed,
			UpstreamForwarded: false,
			UpstreamBytesSent: 0,
			ErrorCode:         code,
			ErrorMessage:      safeMsg,
			UpdatedAt:         h.nowFn().UTC(),
			CompletedAt:       h.nowFn().UTC(),
		})
		h.emitPushAudit(ctx, nil, "push.failed", req, sessionID, repoIDPtr, manifestDigest, hasLFS, lfsCount, lfsTotalBytes, nil, nil, finalEffect, finalStatus, false, 0, code)
		h.writeSidebandLines(req.SidebandWriter, extraSecrets, "DENY: "+safeMsg)
		return ReceivePackOutcome{
			SessionID:          sessionID,
			Status:             domain.PushSessionStatusFailed,
			Effect:             domain.PolicyEffectDeny,
			UnpackOK:           true,
			RefResults:         failAllRefs(req.RefUpdates, safeMsg),
			PushManifestDigest: manifestDigest,
			ErrorCode:          code,
			ErrorMessage:       safeMsg,
			HTTPStatus:         0,
		}, nil
	}

	primaryReason := primaryPolicyReasonMessage(evalOutcome.result)
	var consumedReleaseID *uuid.UUID

	// 10. Enforcement / Approval Release / LFS Verification.
	if egressMode == domain.EgressModeEnforceBlock {
		switch effectiveEffect {
		case domain.PolicyEffectDeny, domain.PolicyEffectQuarantine, domain.PolicyEffectRequireRemediation:
			termStatus := domain.PushSessionStatusBlocked
			auditEventType := "push.blocked"
			if effectiveEffect == domain.PolicyEffectQuarantine {
				termStatus = domain.PushSessionStatusQuarantined
				auditEventType = "push.quarantined"
			}
			errCode := "POLICY_" + string(effectiveEffect)
			finalStatus = termStatus
			finalEffect = effectiveEffect
			_, _ = h.store.CompletePushSession(ctx, persistence.CompletePushSessionParams{
				ID:                sessionID,
				Status:            termStatus,
				UpstreamForwarded: false,
				UpstreamBytesSent: 0,
				ErrorCode:         errCode,
				ErrorMessage:      primaryReason,
				UpdatedAt:         h.nowFn().UTC(),
				CompletedAt:       h.nowFn().UTC(),
			})
			h.emitPushAudit(ctx, nil, auditEventType, req, sessionID, repoIDPtr, manifestDigest, hasLFS, lfsCount, lfsTotalBytes, &pdRow.ID, nil, finalEffect, finalStatus, false, 0, errCode)
			h.writeSidebandLines(req.SidebandWriter, extraSecrets,
				fmt.Sprintf("%s: %s (push_session_id=%s manifest=%s)", effectiveEffect, primaryReason, sessionID.String(), manifestDigest),
			)
			return ReceivePackOutcome{
				SessionID:          sessionID,
				Status:             termStatus,
				Effect:             effectiveEffect,
				UpstreamForwarded:  false,
				UpstreamBytesSent:  0,
				UnpackOK:           true,
				RefResults:         failAllRefs(req.RefUpdates, string(effectiveEffect)+": "+primaryReason),
				PushManifestDigest: manifestDigest,
				ErrorCode:          errCode,
				ErrorMessage:       primaryReason,
				HTTPStatus:         0,
			}, nil

		case domain.PolicyEffectRequireApproval:
			if !approvalUsable {
				const errCode = "APPROVAL_REQUIRED"
				finalStatus = domain.PushSessionStatusApprovalRequired
				finalEffect = domain.PolicyEffectRequireApproval
				_, _ = h.store.CompletePushSession(ctx, persistence.CompletePushSessionParams{
					ID:                sessionID,
					Status:            domain.PushSessionStatusApprovalRequired,
					UpstreamForwarded: false,
					UpstreamBytesSent: 0,
					ErrorCode:         errCode,
					ErrorMessage:      primaryReason,
					UpdatedAt:         h.nowFn().UTC(),
					CompletedAt:       h.nowFn().UTC(),
				})
				h.emitPushAudit(ctx, nil, "push.approval_required", req, sessionID, repoIDPtr, manifestDigest, hasLFS, lfsCount, lfsTotalBytes, &pdRow.ID, nil, finalEffect, finalStatus, false, 0, errCode)
				h.writeSidebandLines(req.SidebandWriter, extraSecrets,
					fmt.Sprintf("REQUIRE_APPROVAL: %s (push_session_id=%s manifest=%s)", primaryReason, sessionID.String(), manifestDigest),
				)
				return ReceivePackOutcome{
					SessionID:          sessionID,
					Status:             domain.PushSessionStatusApprovalRequired,
					Effect:             domain.PolicyEffectRequireApproval,
					UpstreamForwarded:  false,
					UpstreamBytesSent:  0,
					UnpackOK:           true,
					RefResults:         failAllRefs(req.RefUpdates, "REQUIRE_APPROVAL: "+primaryReason),
					PushManifestDigest: manifestDigest,
					ErrorCode:          errCode,
					ErrorMessage:       primaryReason,
					HTTPStatus:         0,
				}, nil
			}

			allowMissing := h.shouldAllowMissingLFSWhenApproved(ctx, orgBundles, repoBundles, evalOutcome, relRow, approvalUsable, lfsObjects)
			if lfsVerErr := verifyLFSObjectsUpstream(ctx, h.upstream, h.broker, req.Caller, req.Target, lfsObjects, allowMissing, &extraSecrets); lfsVerErr != nil {
				code, safeMsg := safeGatewayError(lfsVerErr, extraSecrets...)
				finalStatus = domain.PushSessionStatusBlocked
				finalEffect = domain.PolicyEffectDeny
				_, _ = h.store.CompletePushSession(ctx, persistence.CompletePushSessionParams{
					ID:                sessionID,
					Status:            domain.PushSessionStatusBlocked,
					UpstreamForwarded: false,
					UpstreamBytesSent: 0,
					ErrorCode:         code,
					ErrorMessage:      safeMsg,
					UpdatedAt:         h.nowFn().UTC(),
					CompletedAt:       h.nowFn().UTC(),
				})
				h.emitPushAudit(ctx, nil, "push.blocked", req, sessionID, repoIDPtr, manifestDigest, hasLFS, lfsCount, lfsTotalBytes, &pdRow.ID, nil, finalEffect, finalStatus, false, 0, code)
				h.writeSidebandLines(req.SidebandWriter, extraSecrets, "DENY: "+safeMsg)
				return ReceivePackOutcome{
					SessionID:          sessionID,
					Status:             domain.PushSessionStatusBlocked,
					Effect:             domain.PolicyEffectDeny,
					UpstreamForwarded:  false,
					UpstreamBytesSent:  0,
					UnpackOK:           true,
					RefResults:         failAllRefs(req.RefUpdates, safeMsg),
					PushManifestDigest: manifestDigest,
					ErrorCode:          code,
					ErrorMessage:       safeMsg,
					HTTPStatus:         0,
				}, nil
			}

			var failOutcome *ReceivePackOutcome
			consumedReleaseID, failOutcome = h.consumeApprovalReleaseTx(ctx, req, sessionID, repoIDPtr, manifestDigest, hasLFS, lfsCount, lfsTotalBytes, pdRow.ID, extraSecrets)
			if failOutcome != nil {
				finalStatus = failOutcome.Status
				finalEffect = failOutcome.Effect
				return *failOutcome, nil
			}
			effectiveEffect = domain.PolicyEffectAllow

		case domain.PolicyEffectAllow:
			allowMissing := h.shouldAllowMissingLFSWhenApproved(ctx, orgBundles, repoBundles, evalOutcome, relRow, approvalUsable, lfsObjects)
			if lfsVerErr := verifyLFSObjectsUpstream(ctx, h.upstream, h.broker, req.Caller, req.Target, lfsObjects, allowMissing, &extraSecrets); lfsVerErr != nil {
				code, safeMsg := safeGatewayError(lfsVerErr, extraSecrets...)
				finalStatus = domain.PushSessionStatusBlocked
				finalEffect = domain.PolicyEffectDeny
				_, _ = h.store.CompletePushSession(ctx, persistence.CompletePushSessionParams{
					ID:                sessionID,
					Status:            domain.PushSessionStatusBlocked,
					UpstreamForwarded: false,
					UpstreamBytesSent: 0,
					ErrorCode:         code,
					ErrorMessage:      safeMsg,
					UpdatedAt:         h.nowFn().UTC(),
					CompletedAt:       h.nowFn().UTC(),
				})
				h.emitPushAudit(ctx, nil, "push.blocked", req, sessionID, repoIDPtr, manifestDigest, hasLFS, lfsCount, lfsTotalBytes, &pdRow.ID, nil, finalEffect, finalStatus, false, 0, code)
				h.writeSidebandLines(req.SidebandWriter, extraSecrets, "DENY: "+safeMsg)
				return ReceivePackOutcome{
					SessionID:          sessionID,
					Status:             domain.PushSessionStatusBlocked,
					Effect:             domain.PolicyEffectDeny,
					UpstreamForwarded:  false,
					UpstreamBytesSent:  0,
					UnpackOK:           true,
					RefResults:         failAllRefs(req.RefUpdates, safeMsg),
					PushManifestDigest: manifestDigest,
					ErrorCode:          code,
					ErrorMessage:       safeMsg,
					HTTPStatus:         0,
				}, nil
			}
			if approvalUsable {
				var failOutcome *ReceivePackOutcome
				consumedReleaseID, failOutcome = h.consumeApprovalReleaseTx(ctx, req, sessionID, repoIDPtr, manifestDigest, hasLFS, lfsCount, lfsTotalBytes, pdRow.ID, extraSecrets)
				if failOutcome != nil {
					finalStatus = failOutcome.Status
					finalEffect = failOutcome.Effect
					return *failOutcome, nil
				}
			}
		}
	}

	wouldBlockInPassive := egressMode == domain.EgressModePassiveAudit && (effectiveEffect != domain.PolicyEffectAllow || stageAOrBInfraFailed)
	if wouldBlockInPassive {
		h.metrics.IncPushPassiveAuditWouldBlock(string(delivery), string(effectiveEffect))
		if delivery == domain.PassiveAuditDeliveryInlineWarn {
			warnReason := primaryReason
			if stageAOrBInfraFailed && infraReason != "" && effectiveEffect == domain.PolicyEffectAllow {
				warnReason = infraReason
			}
			h.writeSidebandLines(req.SidebandWriter, extraSecrets,
				fmt.Sprintf("PASSIVE_AUDIT WARNING (%s): push would be blocked under ENFORCE_BLOCK (%s)", effectiveEffect, warnReason),
			)
		}
	}

	// 11. Guard empty upstream token before attempting upstream POST /git-receive-pack.
	if strings.TrimSpace(req.UpstreamToken) == "" {
		const code = "UPSTREAM_AUTH_UNAVAILABLE"
		const safeMsg = "no upstream write credential available for target destination"
		finalStatus = domain.PushSessionStatusFailed
		finalEffect = effectiveEffect
		if wouldBlockInPassive {
			finalStatus = domain.PushSessionStatusObservedWouldBlock
		}
		_, _ = h.store.CompletePushSession(ctx, persistence.CompletePushSessionParams{
			ID:                sessionID,
			Status:            finalStatus,
			UpstreamForwarded: false,
			UpstreamBytesSent: 0,
			ErrorCode:         code,
			ErrorMessage:      safeMsg,
			UpdatedAt:         h.nowFn().UTC(),
			CompletedAt:       h.nowFn().UTC(),
		})
		h.emitPushAudit(ctx, nil, "push.failed", req, sessionID, repoIDPtr, manifestDigest, hasLFS, lfsCount, lfsTotalBytes, pdIDPtr, consumedReleaseID, effectiveEffect, finalStatus, false, 0, code)
		h.writeSidebandLines(req.SidebandWriter, extraSecrets, "ERROR: "+safeMsg)
		return ReceivePackOutcome{
			SessionID:          sessionID,
			Status:             finalStatus,
			Effect:             effectiveEffect,
			UpstreamForwarded:  false,
			UpstreamBytesSent:  0,
			UnpackOK:           true,
			RefResults:         failAllRefs(req.RefUpdates, safeMsg),
			PushManifestDigest: manifestDigest,
			ErrorCode:          code,
			ErrorMessage:       safeMsg,
			HTTPStatus:         0,
		}, nil
	}

	// 12. Clean Repack & Upstream Forward.
	_ = h.updatePushSessionStatus(ctx, sessionID, domain.PushSessionStatusForwarding)

	var upstreamPayload bytes.Buffer
	for i, ru := range unpackRes.RefUpdates {
		if i == 0 {
			_ = writePktLine(&upstreamPayload, []byte(fmt.Sprintf("%s %s %s\x00report-status\n", ru.OldOID, ru.NewOID, ru.RefName)))
		} else {
			_ = writePktLine(&upstreamPayload, []byte(fmt.Sprintf("%s %s %s\n", ru.OldOID, ru.NewOID, ru.RefName)))
		}
	}
	_ = writeFlushPkt(&upstreamPayload)

	if unpackRes.NeedsPack() {
		if _, packErr := quarantine.BuildCleanPack(ctx, unpackRes, &upstreamPayload, quarantine.CleanPackOptions{UseOfsDelta: false}); packErr != nil {
			code, safeMsg := safeGatewayError(packErr, extraSecrets...)
			finalStatus = domain.PushSessionStatusFailed
			finalEffect = effectiveEffect
			_, _ = h.store.CompletePushSession(ctx, persistence.CompletePushSessionParams{
				ID:                sessionID,
				Status:            domain.PushSessionStatusFailed,
				UpstreamForwarded: false,
				UpstreamBytesSent: 0,
				ErrorCode:         code,
				ErrorMessage:      safeMsg,
				UpdatedAt:         h.nowFn().UTC(),
				CompletedAt:       h.nowFn().UTC(),
			})
			h.emitPushAudit(ctx, nil, "push.failed", req, sessionID, repoIDPtr, manifestDigest, hasLFS, lfsCount, lfsTotalBytes, pdIDPtr, consumedReleaseID, effectiveEffect, finalStatus, false, 0, code)
			h.writeSidebandLines(req.SidebandWriter, extraSecrets, "ERROR: "+safeMsg)
			return ReceivePackOutcome{
				SessionID:          sessionID,
				Status:             domain.PushSessionStatusFailed,
				Effect:             effectiveEffect,
				UpstreamForwarded:  false,
				UpstreamBytesSent:  0,
				UnpackOK:           false,
				UnpackMessage:      safeMsg,
				RefResults:         failAllRefs(req.RefUpdates, safeMsg),
				PushManifestDigest: manifestDigest,
				ErrorCode:          code,
				ErrorMessage:       safeMsg,
				HTTPStatus:         0,
			}, nil
		}
	}

	forwardStart := h.nowFn().UTC()
	upStatus, upBody, bytesSent, upErr := h.upstream.ReceivePack(ctx, req.Target.OwnerRepo, req.UpstreamToken, &upstreamPayload)
	h.metrics.ObservePushPhase(string(transport), string(egressMode), "forward", h.nowFn().UTC().Sub(forwardStart))
	if bytesSent > 0 {
		h.metrics.AddPushUpstreamBytes(string(egressMode), "receive_pack", bytesSent)
	}

	upstreamForwarded := upErr == nil && bytesSent > 0
	upUnpackOK, upUnpackMsg, refResults := parseUpstreamReceivePackOutcome(upStatus, upBody, upErr, req.RefUpdates, extraSecrets)

	allRefsOK := upUnpackOK && upErr == nil && upStatus == http.StatusOK
	for _, rr := range refResults {
		if !rr.OK {
			allRefsOK = false
			break
		}
	}

	var errCode, errMsg string
	auditEventType := "push.completed"
	switch {
	case !allRefsOK:
		finalStatus = domain.PushSessionStatusFailed
		auditEventType = "push.failed"
		errCode = "UPSTREAM_RECEIVE_PACK_FAILED"
		errMsg = upUnpackMsg
		if errMsg == "" {
			errMsg = fmt.Sprintf("upstream receive-pack rejected push (status %d)", upStatus)
		}
	case wouldBlockInPassive:
		finalStatus = domain.PushSessionStatusObservedWouldBlock
		auditEventType = "push.observed_would_block"
	default:
		finalStatus = domain.PushSessionStatusCompleted
	}
	finalEffect = effectiveEffect

	_, _ = h.store.CompletePushSession(ctx, persistence.CompletePushSessionParams{
		ID:                sessionID,
		Status:            finalStatus,
		UpstreamForwarded: upstreamForwarded,
		UpstreamBytesSent: bytesSent,
		ErrorCode:         errCode,
		ErrorMessage:      errMsg,
		UpdatedAt:         h.nowFn().UTC(),
		CompletedAt:       h.nowFn().UTC(),
	})

	auditErrCode := errCode
	if auditErrCode == "" && wouldBlockInPassive {
		auditErrCode = infraErrCode
	}
	h.emitPushAudit(ctx, nil, auditEventType, req, sessionID, repoIDPtr, manifestDigest, hasLFS, lfsCount, lfsTotalBytes, pdIDPtr, consumedReleaseID, effectiveEffect, finalStatus, upstreamForwarded, bytesSent, auditErrCode)

	if allRefsOK {
		if wouldBlockInPassive {
			h.writeSidebandLines(req.SidebandWriter, extraSecrets,
				fmt.Sprintf("PASSIVE_AUDIT OBSERVED_WOULD_BLOCK: push forwarded upstream (push_session_id=%s manifest=%s)", sessionID.String(), manifestDigest),
			)
		} else {
			h.writeSidebandLines(req.SidebandWriter, extraSecrets,
				fmt.Sprintf("ALLOW: push verified and forwarded cleanly (push_session_id=%s manifest=%s)", sessionID.String(), manifestDigest),
			)
		}
	} else {
		h.writeSidebandLines(req.SidebandWriter, extraSecrets, "ERROR: "+errMsg)
	}

	return ReceivePackOutcome{
		SessionID:          sessionID,
		Status:             finalStatus,
		Effect:             effectiveEffect,
		UpstreamForwarded:  upstreamForwarded,
		UpstreamBytesSent:  bytesSent,
		UpstreamStatusLine: fmt.Sprintf("HTTP %d", upStatus),
		UnpackOK:           upUnpackOK,
		UnpackMessage:      upUnpackMsg,
		RefResults:         refResults,
		PushManifestDigest: manifestDigest,
		ErrorCode:          errCode,
		ErrorMessage:       errMsg,
		HTTPStatus:         0,
	}, nil
}

// --- Upstream Ref Resolution & Ephemeral Baseline Fetch ---

type upstreamRefResolver struct {
	refs map[string]string
}

func (r *upstreamRefResolver) ResolveRef(_ context.Context, refName string) (string, bool, error) {
	if r == nil || len(r.refs) == 0 {
		return "", false, nil
	}
	oid, ok := r.refs[refName]
	return oid, ok, nil
}

func (r *upstreamRefResolver) ListBaselineOIDs(_ context.Context) ([]string, error) {
	if r == nil || len(r.refs) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(r.refs))
	out := make([]string, 0, len(r.refs))
	for _, oid := range r.refs {
		if oid == "" || oid == quarantine.ZeroOID {
			continue
		}
		if _, ok := seen[oid]; !ok {
			seen[oid] = struct{}{}
			out = append(out, oid)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (h *PipelineReceivePackHandler) resolveUpstreamRefs(ctx context.Context, req ReceivePackRequest) (map[string]string, error) {
	if req.Target.Repository != nil || strings.TrimSpace(req.UpstreamToken) != "" {
		status, _, _, refs, err := h.upstream.InfoRefs(ctx, req.Target.OwnerRepo, "git-receive-pack", req.UpstreamToken)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, domain.Unavailable("UPSTREAM_INFO_REFS_FAILED", fmt.Sprintf("upstream git-receive-pack info/refs returned status %d", status))
		}
		return refs, nil
	}

	// Unregistered destination with no write token: try read-safe git-upload-pack info/refs,
	// falling back to empty refs on 404/unavailable so Stage C evaluates !destination.registered -> DENY.
	status, _, _, refs, err := h.upstream.InfoRefs(ctx, req.Target.OwnerRepo, "git-upload-pack", "")
	if err != nil || status != http.StatusOK {
		return map[string]string{}, nil
	}
	return refs, nil
}

func (h *PipelineReceivePackHandler) fetchEphemeralBaseline(
	ctx context.Context,
	req ReceivePackRequest,
	upstreamRefs map[string]string,
	extraSecrets *[]string,
) (string, error) {
	var readToken string
	if h.broker != nil {
		readAuth, err := h.broker.ResolveUpstreamAuth(ctx, TokenScopeRead, req.Caller, req.Target)
		if err != nil {
			return "", err
		}
		readToken = readAuth.Token
		if extraSecrets != nil {
			*extraSecrets = collectExtraSecrets(append(*extraSecrets, readAuth.ExtraSecrets...)...)
		}
	}

	seenOID := make(map[string]struct{}, len(upstreamRefs))
	var wantOIDs []string
	for _, oid := range upstreamRefs {
		if oid == "" || oid == quarantine.ZeroOID || !is40HexLower(oid) {
			continue
		}
		if _, ok := seenOID[oid]; !ok {
			seenOID[oid] = struct{}{}
			wantOIDs = append(wantOIDs, oid)
		}
	}
	sort.Strings(wantOIDs)
	if len(wantOIDs) == 0 {
		return "", nil
	}

	var wantBuf bytes.Buffer
	for _, oid := range wantOIDs {
		_ = writePktLine(&wantBuf, []byte("want "+oid+"\n"))
	}
	_ = writeFlushPkt(&wantBuf)
	_ = writePktLine(&wantBuf, []byte("done\n"))

	var respBuf bytes.Buffer
	status, err := h.upstream.UploadPack(ctx, req.Target.OwnerRepo, readToken, &wantBuf, &respBuf)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", domain.Unavailable("UPSTREAM_BASELINE_FETCH_FAILED", fmt.Sprintf("upstream git-upload-pack returned status %d", status))
	}

	packBytes, err := extractPackFromUploadPackResponse(respBuf.Bytes())
	if err != nil {
		return "", err
	}

	baselineDir, err := os.MkdirTemp("", "custodian-baseline-*")
	if err != nil {
		return "", domain.WrapError(domain.ErrInternal, "BASELINE_MKDIR_FAILED", "failed creating baseline repo dir", err)
	}
	if err := os.Chmod(baselineDir, 0o700); err != nil {
		_ = os.RemoveAll(baselineDir)
		return "", err
	}
	homeDir, err := os.MkdirTemp("", "custodian-baseline-home-*")
	if err != nil {
		_ = os.RemoveAll(baselineDir)
		return "", err
	}
	defer func() { _ = os.RemoveAll(homeDir) }()

	cleanupOnErr := true
	defer func() {
		if cleanupOnErr {
			_ = os.RemoveAll(baselineDir)
		}
	}()

	if err := runPipelineHardenedGit(ctx, h.gitBinary, homeDir, "", nil, "init", "--bare", "--initial-branch=main", "--", baselineDir); err != nil {
		return "", domain.WrapError(domain.ErrInternal, "BASELINE_INIT_FAILED", "failed initializing baseline bare repo", err)
	}
	if len(packBytes) > 0 {
		if err := runPipelineHardenedGit(ctx, h.gitBinary, homeDir, baselineDir, bytes.NewReader(packBytes), "index-pack", "--strict", "--stdin"); err != nil {
			return "", domain.WrapError(domain.ErrUnavailable, "BASELINE_INDEX_FAILED", "failed indexing upstream baseline pack", err)
		}
	}

	var refScript bytes.Buffer
	refNames := make([]string, 0, len(upstreamRefs))
	for refName := range upstreamRefs {
		if strings.HasPrefix(refName, "refs/") && !strings.HasSuffix(refName, "^{}") {
			refNames = append(refNames, refName)
		}
	}
	sort.Strings(refNames)
	for _, refName := range refNames {
		oid := upstreamRefs[refName]
		if !is40HexLower(oid) || oid == quarantine.ZeroOID {
			continue
		}
		refScript.WriteString("update ")
		refScript.WriteString(refName)
		refScript.WriteByte(0)
		refScript.WriteString(oid)
		refScript.WriteByte(0)
		refScript.WriteByte(0)
	}
	if refScript.Len() > 0 {
		if err := runPipelineHardenedGit(ctx, h.gitBinary, homeDir, baselineDir, &refScript, "update-ref", "--stdin", "-z"); err != nil {
			return "", domain.WrapError(domain.ErrUnavailable, "BASELINE_REF_UPDATE_FAILED", "failed updating baseline refs", err)
		}
	}

	cleanupOnErr = false
	return baselineDir, nil
}

func extractPackFromUploadPackResponse(raw []byte) ([]byte, error) {
	if bytes.HasPrefix(raw, []byte("PACK")) {
		return raw, nil
	}
	rd := bytes.NewReader(raw)
	for {
		if rd.Len() >= 4 {
			pos := len(raw) - rd.Len()
			if bytes.HasPrefix(raw[pos:], []byte("PACK")) {
				return raw[pos:], nil
			}
		}
		payload, flush, err := readPktLine(rd)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, domain.WrapError(domain.ErrUnavailable, "BASELINE_PARSE_FAILED", "malformed upstream upload-pack response", err)
		}
		if flush {
			continue
		}
		trimmed := strings.TrimRight(string(payload), "\r\n")
		if trimmed == "NAK" || strings.HasPrefix(trimmed, "ACK ") || strings.HasPrefix(trimmed, "shallow ") || strings.HasPrefix(trimmed, "unshallow ") {
			continue
		}
		if len(payload) > 0 && payload[0] == 0x01 {
			var out bytes.Buffer
			out.Write(payload[1:])
			for {
				p2, f2, e2 := readPktLine(rd)
				if e2 != nil {
					if errors.Is(e2, io.EOF) {
						return out.Bytes(), nil
					}
					return nil, domain.WrapError(domain.ErrUnavailable, "BASELINE_PARSE_FAILED", "malformed sideband upload-pack stream", e2)
				}
				if f2 {
					continue
				}
				if len(p2) > 0 && p2[0] == 0x01 {
					out.Write(p2[1:])
				} else if len(p2) > 0 && p2[0] == 0x03 {
					return nil, domain.Unavailable("BASELINE_UPSTREAM_ERR", "upstream upload-pack returned error")
				}
			}
		}
	}
	pos := len(raw) - rd.Len()
	return raw[pos:], nil
}

func runPipelineHardenedGit(ctx context.Context, gitBinary, homeDir, gitDir string, stdin io.Reader, subargs ...string) error {
	args := append([]string(nil), checkout.HardenedGitFlags(false)...)
	if gitDir != "" {
		args = append(args, "-C", gitDir)
	}
	args = append(args, subargs...)
	cmd := exec.CommandContext(ctx, gitBinary, args...)
	cmd.Env = checkout.CleanGitEnv(homeDir, false, false, "", "")
	if stdin != nil {
		cmd.Stdin = stdin
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %s", err, checkout.SanitizeGitOutput(stderr.String()))
	}
	return nil
}

// --- Stage A / Stage B / Stage C Helpers ---

func assembleBoundedUnifiedDiff(workspaceDir string, maxBytes int64) string {
	if strings.TrimSpace(workspaceDir) == "" || maxBytes <= 0 {
		return ""
	}
	commitsRoot := filepath.Join(workspaceDir, "history", "commits")
	entries, err := os.ReadDir(commitsRoot)
	if err != nil {
		return ""
	}
	var commitNames []string
	for _, e := range entries {
		if e.IsDir() {
			commitNames = append(commitNames, e.Name())
		}
	}
	sort.Strings(commitNames)

	var buf bytes.Buffer
	for _, commitName := range commitNames {
		if int64(buf.Len()) >= maxBytes {
			break
		}
		cDir := filepath.Join(commitsRoot, commitName)
		files, err := os.ReadDir(cDir)
		if err != nil {
			continue
		}
		var patchFiles []string
		for _, f := range files {
			if f.IsDir() {
				continue
			}
			n := f.Name()
			if n == "diff.patch" || (strings.HasPrefix(n, "diff_") && strings.HasSuffix(n, ".patch")) {
				patchFiles = append(patchFiles, n)
			}
		}
		sort.Strings(patchFiles)
		for _, pf := range patchFiles {
			if int64(buf.Len()) >= maxBytes {
				break
			}
			f, err := os.Open(filepath.Join(cDir, pf))
			if err != nil {
				continue
			}
			rem := maxBytes - int64(buf.Len())
			_, _ = io.Copy(&buf, io.LimitReader(f, rem))
			_ = f.Close()
		}
	}
	return buf.String()
}

func assembleStageBContextDiff(commits []quarantine.ExtractedCommit, unifiedDiff string, maxTotalBytes int64, scrubFn func(string) string) string {
	if maxTotalBytes <= 0 {
		maxTotalBytes = decisions.DefaultMaxDiffBytes
	}
	if scrubFn == nil {
		scrubFn = func(s string) string { return s }
	}

	commitBudget := int64(maxStageBCommitMessagesBytes)
	if commitBudget > maxTotalBytes {
		commitBudget = maxTotalBytes
	}
	msgSection := formatBoundedCommitMessages(commits, commitBudget, scrubFn)
	scrubbedDiff := scrubFn(unifiedDiff)

	if msgSection == "" {
		return truncateUTF8Bytes(scrubbedDiff, maxTotalBytes)
	}
	if scrubbedDiff == "" {
		return scrubFn(truncateUTF8Bytes(msgSection, maxTotalBytes))
	}

	const diffSep = "\n--- Unified Diff ---\n"
	rem := maxTotalBytes - int64(len(msgSection)) - int64(len(diffSep))
	if rem <= 0 {
		return scrubFn(truncateUTF8Bytes(msgSection, maxTotalBytes))
	}
	return scrubFn(msgSection + diffSep + truncateUTF8Bytes(scrubbedDiff, rem))
}

func formatBoundedCommitMessages(commits []quarantine.ExtractedCommit, maxBytes int64, scrubFn func(string) string) string {
	if maxBytes <= 0 || len(commits) == 0 {
		return ""
	}
	const header = "--- Commit Messages ---\n"
	var entries []string
	for _, c := range commits {
		msg := strings.TrimSpace(scrubFn(c.Message))
		if msg == "" {
			continue
		}
		entries = append(entries, fmt.Sprintf("Commit %s:\n%s\n", strings.TrimSpace(c.OID), msg))
	}
	if len(entries) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString(header)
	for i, entry := range entries {
		if i > 0 {
			if int64(b.Len())+1 >= maxBytes {
				break
			}
			b.WriteByte('\n')
		}
		rem := maxBytes - int64(b.Len())
		if rem <= 0 {
			break
		}
		if int64(len(entry)) > rem {
			b.WriteString(truncateUTF8Bytes(entry, rem))
			break
		}
		b.WriteString(entry)
	}
	out := b.String()
	if int64(len(out)) > maxBytes {
		return truncateUTF8Bytes(out, maxBytes)
	}
	return out
}

func truncateUTF8Bytes(s string, maxBytes int64) string {
	if maxBytes <= 0 {
		return ""
	}
	if int64(len(s)) <= maxBytes {
		return s
	}
	cut := int(maxBytes)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func shouldTriggerStageB(triggers []string, summary inspection.InspectionSummary, target ResolvedTarget) bool {
	if len(triggers) == 0 {
		return false
	}
	for _, tr := range triggers {
		switch strings.TrimSpace(tr) {
		case "restricted_ip_finding":
			if summary.RestrictedIPMatches > 0 || summary.IPHeaderStripMatches > 0 {
				return true
			}
		case "concealment_finding":
			if summary.ConcealmentFindings > 0 {
				return true
			}
		case "restricted_repository":
			if target.Repository != nil && target.Repository.Classification == domain.ClassificationRestricted {
				return true
			}
		case "high_risk_change":
			if summary.CriticalSecrets > 0 || summary.HighVulnerabilities > 0 || summary.HighSASTFindings > 0 {
				return true
			}
		}
	}
	return false
}

func buildFallbackFailedAssessment(sessionID, artifactID uuid.UUID, modelRoute, inputDigest string, now time.Time) domain.ModelAssessment {
	id, err := domain.NewID()
	if err != nil {
		id = sessionID
	}
	if strings.TrimSpace(modelRoute) == "" {
		modelRoute = "approved-code-review"
	}
	if _, err := domain.ParseSHA256Digest(inputDigest); err != nil {
		inputDigest = domain.SHA256Hex([]byte(sessionID.String()))
	}
	res := domain.AssessmentResult{
		SchemaVersion:  "1",
		AssessmentType: prompts.AssessmentTypeIPProvenance,
		Risk:           domain.RiskLevelNone,
		Disposition:    domain.DispositionIndeterminate,
		Confidence:     0,
		Summary:        "Stage B assessment failed",
		Findings:       []domain.AssessmentFinding{},
		Limitations:    []string{"STAGE_B_FAILED"},
	}
	outDigest, err := domain.CanonicalJSONDigest(res)
	if err != nil {
		outDigest = domain.SHA256Hex([]byte("failed"))
	}
	sid := sessionID
	return domain.ModelAssessment{
		ID:             id,
		ProposalID:     uuid.Nil,
		PushSessionID:  &sid,
		ArtifactID:     artifactID,
		ModelRoute:     modelRoute,
		ModelVersion:   "stage-b-error",
		PromptVersion:  "v1",
		AssessmentType: prompts.AssessmentTypeIPProvenance,
		Status:         domain.AssessmentStatusFailed,
		Result:         res,
		EvidenceIDs:    []string{},
		InputDigest:    inputDigest,
		OutputDigest:   outDigest,
		CreatedAt:      now,
	}
}

func buildPushPolicyInput(
	req ReceivePackRequest,
	unpackRes *quarantine.UnpackResult,
	summary inspection.InspectionSummary,
	assessment domain.ModelAssessment,
	effClass domain.Classification,
	hasLFS bool,
	lfsCount, lfsTotalBytes int64,
	refNames []string,
	approvalPresent bool,
	manifestDigest string,
) policy.PolicyInput {
	fact := decisions.ToPolicyAssessmentFact(assessment)
	var repoInput policy.RepositoryInput
	var repoIDStr string
	if req.Target.Repository != nil {
		repoIDStr = req.Target.Repository.ID.String()
		allowed := append([]string(nil), req.Target.AllowedModelRoutes...)
		if allowed == nil {
			allowed = []string{}
		}
		repoInput = policy.RepositoryInput{
			ID:                   repoIDStr,
			FullName:             req.Target.Repository.FullName,
			Classification:       string(req.Target.Repository.Classification),
			Enabled:              req.Target.Repository.Enabled,
			AllowedModelRoutes:   allowed,
			GitHubRepositoryID:   req.Target.Repository.GitHubRepositoryID,
			GitHubInstallationID: req.Target.Repository.GitHubInstallationID,
		}
	} else {
		repoInput = policy.RepositoryInput{
			FullName:           req.Target.OwnerRepo,
			Classification:     string(effClass),
			AllowedModelRoutes: []string{},
		}
	}

	ownerPart := ""
	if o, _, err := (domain.Repository{FullName: req.Target.OwnerRepo}).OwnerRepo(); err == nil {
		ownerPart = o
	}

	groups := append([]string(nil), req.Caller.Groups...)
	if groups == nil {
		groups = []string{}
	}
	paths := append([]string(nil), unpackRes.ChangedPaths...)
	if paths == nil {
		paths = []string{}
	}
	refsCopy := append([]string(nil), refNames...)
	if refsCopy == nil {
		refsCopy = []string{}
	}

	var totalBlobBytes int64
	for _, b := range unpackRes.Blobs {
		if b.SizeBytes > 0 {
			if b.SizeBytes > math.MaxInt64-totalBlobBytes {
				totalBlobBytes = math.MaxInt64
				break
			}
			totalBlobBytes += b.SizeBytes
		}
	}

	baseCommit := ""
	targetRef := ""
	if len(req.RefUpdates) > 0 {
		baseCommit = req.RefUpdates[0].OldOID
		targetRef = req.RefUpdates[0].RefName
	}

	return policy.PolicyInput{
		Stage:    policy.StagePushEgress,
		Findings: pushSummaryToFindingsInput(summary),
		Assessment: policy.AssessmentInput{
			Status:         fact.Status,
			IPRisk:         fact.IPRisk,
			Risk:           fact.Risk,
			Disposition:    fact.Disposition,
			ModelRoute:     fact.ModelRoute,
			ModelVersion:   fact.ModelVersion,
			PromptVersion:  fact.PromptVersion,
			AssessmentType: fact.AssessmentType,
		},
		Change: policy.ChangeInput{
			Paths:          paths,
			FileCount:      int64(len(unpackRes.Blobs)),
			TotalBytes:     totalBlobBytes,
			ManifestDigest: manifestDigest,
			BaseCommit:     baseCommit,
			TargetRef:      targetRef,
		},
		Repository: repoInput,
		Principal: policy.PrincipalInput{
			ID:            req.Caller.Principal.ID.String(),
			Kind:          string(req.Caller.Principal.Kind),
			Subject:       req.Caller.Principal.Subject,
			DisplayName:   req.Caller.Principal.DisplayName,
			VerifiedEmail: req.Caller.Principal.VerifiedEmail,
			Groups:        groups,
			Roles:         []string{},
		},
		Destination: policy.DestinationInput{
			ID:             repoIDStr,
			Name:           req.Target.OwnerRepo,
			Host:           req.Target.Host,
			Registered:     req.Target.Registered,
			External:       req.Target.External,
			Classification: string(effClass),
			Org:            ownerPart,
			Owner:          ownerPart,
		},
		Push: policy.PushInput{
			HasLFS:                 hasLFS,
			LFSObjectCount:         lfsCount,
			LFSTotalBytes:          lfsTotalBytes,
			RefNames:               refsCopy,
			CommitCount:            int64(len(unpackRes.Commits)),
			EgressMode:             string(req.Target.EgressMode),
			ApprovalReleasePresent: approvalPresent,
			PushManifestDigest:     manifestDigest,
		},
	}
}

func (h *PipelineReceivePackHandler) persistStageAReport(
	ctx context.Context,
	sessionID, artifactID uuid.UUID,
	report inspection.Report,
) error {
	return h.store.WithTx(ctx, func(tx *persistence.Tx) error {
		for _, sr := range report.ScanRuns {
			ver := strings.TrimSpace(sr.ScannerVersion)
			if ver == "" {
				ver = "unknown"
			}
			sid := sessionID
			_, err := tx.CreateScanRun(ctx, persistence.CreateScanRunParams{
				ID:             sr.ID,
				ProposalID:     uuid.Nil,
				PushSessionID:  &sid,
				ArtifactID:     artifactID,
				Scanner:        sr.Scanner,
				ScannerVersion: ver,
				Status:         sr.Status,
				Coverage:       sr.Coverage,
				StartedAt:      sr.StartedAt,
				CompletedAt:    sr.CompletedAt,
			})
			if err != nil {
				return err
			}
		}
		for _, f := range report.Findings {
			if err := f.ValidateRedacted(); err != nil {
				return err
			}
			var startLine, endLine *int
			if f.StartLine > 0 {
				v := f.StartLine
				startLine = &v
			}
			if f.EndLine > 0 {
				v := f.EndLine
				endLine = &v
			}
			var conf *float64
			if f.Confidence > 0 {
				v := f.Confidence
				conf = &v
			}
			_, err := tx.CreateFinding(ctx, persistence.CreateFindingParams{
				ID:                 f.ID,
				ScanRunID:          f.ScanRunID,
				EvidenceID:         f.EvidenceID,
				Scanner:            f.Scanner,
				Category:           f.Category,
				Severity:           f.Severity,
				RuleID:             f.RuleID,
				Path:               f.Path,
				StartLine:          startLine,
				EndLine:            endLine,
				Fingerprint:        f.Fingerprint,
				EvidenceArtifactID: f.EvidenceArtifactID,
				EvidenceRef:        f.EvidenceRef,
				Baseline:           f.Baseline,
				Confidence:         conf,
				Message:            f.Message,
				Redacted:           f.Redacted,
				Metadata:           f.Metadata,
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func (h *PipelineReceivePackHandler) persistModelAssessment(ctx context.Context, a domain.ModelAssessment) (persistence.ModelAssessmentRow, error) {
	sid := a.PushSessionID
	if sid == nil || *sid == uuid.Nil {
		return persistence.ModelAssessmentRow{}, domain.BadRequest("INVALID_MODEL_ASSESSMENT", "push_session_id is required")
	}
	return h.store.CreateModelAssessment(ctx, persistence.CreateModelAssessmentParams{
		ID:             a.ID,
		ProposalID:     uuid.Nil,
		PushSessionID:  sid,
		ArtifactID:     a.ArtifactID,
		ModelRoute:     a.ModelRoute,
		ModelVersion:   a.ModelVersion,
		PromptVersion:  a.PromptVersion,
		AssessmentType: a.AssessmentType,
		Status:         a.Status,
		Risk:           a.Risk,
		Disposition:    a.Disposition,
		Result:         a.Result,
		EvidenceIDs:    a.EvidenceIDs,
		InputDigest:    a.InputDigest,
		OutputDigest:   a.OutputDigest,
		CreatedAt:      a.CreatedAt,
	})
}

func (h *PipelineReceivePackHandler) updatePushSessionStatus(ctx context.Context, sessionID uuid.UUID, status domain.PushSessionStatus) error {
	if h.store == nil || h.store.Pool() == nil {
		return nil
	}
	_, err := h.store.Pool().Exec(ctx, `UPDATE push_sessions SET status = $2, updated_at = $3 WHERE id = $1`, sessionID, string(status), h.nowFn().UTC().Truncate(time.Microsecond))
	return persistence.MapError(err)
}

func (h *PipelineReceivePackHandler) emitPushAudit(
	ctx context.Context,
	tx *persistence.Tx,
	eventType string,
	req ReceivePackRequest,
	sessionID uuid.UUID,
	repoID *uuid.UUID,
	manifestDigest string,
	hasLFS bool,
	lfsCount, lfsTotalBytes int64,
	policyDecisionID, approvalReleaseID *uuid.UUID,
	effect domain.PolicyEffect,
	status domain.PushSessionStatus,
	upstreamForwarded bool,
	upstreamBytes int64,
	errCode string,
) {
	payload := h.buildAuditPayload(req, sessionID, repoID, manifestDigest, hasLFS, lfsCount, lfsTotalBytes, policyDecisionID, approvalReleaseID, effect, status, upstreamForwarded, upstreamBytes, errCode)
	in := audit.AppendInput{
		EventType:    eventType,
		ActorID:      &req.Caller.Principal.ID,
		ResourceType: "push_session",
		ResourceID:   sessionID,
		Payload:      payload,
		CreatedAt:    h.nowFn().UTC(),
	}
	if tx != nil {
		_, _ = h.auditSvc.AppendTx(ctx, tx, in)
		return
	}
	_, _ = h.auditSvc.Append(ctx, in)
}

func (h *PipelineReceivePackHandler) buildAuditPayload(
	req ReceivePackRequest,
	sessionID uuid.UUID,
	repoID *uuid.UUID,
	manifestDigest string,
	hasLFS bool,
	lfsCount, lfsTotalBytes int64,
	policyDecisionID, approvalReleaseID *uuid.UUID,
	effect domain.PolicyEffect,
	status domain.PushSessionStatus,
	upstreamForwarded bool,
	upstreamBytes int64,
	errCode string,
) json.RawMessage {
	m := map[string]any{
		"push_session_id":     sessionID.String(),
		"principal_id":        req.Caller.Principal.ID.String(),
		"principal_subject":   req.Caller.Principal.Subject,
		"auth_method":         req.Caller.AuthMethod,
		"destination":         req.Target.CanonicalDestination,
		"transport":           string(req.Transport),
		"egress_mode":         string(req.Target.EgressMode),
		"enforced":            req.Target.EgressMode != domain.EgressModePassiveAudit,
		"has_lfs":             hasLFS,
		"lfs_object_count":    lfsCount,
		"lfs_total_bytes":     lfsTotalBytes,
		"effect":              string(effect),
		"status":              string(status),
		"upstream_forwarded":  upstreamForwarded,
		"upstream_bytes_sent": upstreamBytes,
	}
	if req.Caller.SSHKeyID != "" {
		m["ssh_key_id"] = req.Caller.SSHKeyID
	}
	if req.Caller.SSHCertSerial != 0 {
		m["ssh_cert_serial"] = req.Caller.SSHCertSerial
	}
	if repoID != nil && *repoID != uuid.Nil {
		m["repository_id"] = repoID.String()
	}
	if manifestDigest != "" {
		m["push_manifest_digest"] = manifestDigest
	}
	if policyDecisionID != nil && *policyDecisionID != uuid.Nil {
		m["policy_decision_id"] = policyDecisionID.String()
	}
	if approvalReleaseID != nil && *approvalReleaseID != uuid.Nil {
		m["approval_release_id"] = approvalReleaseID.String()
	}
	if errCode != "" {
		m["error_code"] = errCode
	}
	b, _ := json.Marshal(m)
	return b
}

func (h *PipelineReceivePackHandler) writeSidebandLines(w io.Writer, extraSecrets []string, lines ...string) {
	if w == nil {
		return
	}
	redactor := inspection.NewRedactor(extraSecrets...)
	for _, rawLine := range lines {
		clean := strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(rawLine, "\r", " "), "\n", " "))
		if clean == "" {
			continue
		}
		clean = redactor.ScrubString(clean)
		for len(clean) > 0 {
			chunk := clean
			if len(chunk) > maxSidebandLineBytes {
				chunk = clean[:maxSidebandLineBytes]
				clean = clean[maxSidebandLineBytes:]
			} else {
				clean = ""
			}
			_, _ = io.WriteString(w, chunk+"\n")
		}
	}
}

func (h *PipelineReceivePackHandler) acquireRepoSlot(ctx context.Context, key string) (func(), error) {
	if h.repoLimit <= 0 {
		return func() {}, nil
	}
	h.repoSemMu.Lock()
	sem, ok := h.repoSems[key]
	if !ok {
		sem = make(chan struct{}, h.repoLimit)
		h.repoSems[key] = sem
	}
	h.repoSemMu.Unlock()

	select {
	case sem <- struct{}{}:
		return func() { <-sem }, nil
	case <-ctx.Done():
		return func() {}, ctx.Err()
	}
}

func (h *PipelineReceivePackHandler) acquireScanBudget(ctx context.Context) (func(), error) {
	if h.scanBudget == nil {
		return func() {}, nil
	}
	select {
	case h.scanBudget <- struct{}{}:
		return func() { <-h.scanBudget }, nil
	case <-ctx.Done():
		return func() {}, ctx.Err()
	}
}

func parseUpstreamReceivePackOutcome(
	status int,
	body []byte,
	reqErr error,
	refUpdates []quarantine.RefUpdate,
	extraSecrets []string,
) (unpackOK bool, unpackMsg string, results []RefResult) {
	if reqErr != nil || status != http.StatusOK {
		msg := fmt.Sprintf("upstream returned status %d", status)
		if reqErr != nil {
			_, msg = safeGatewayError(reqErr, extraSecrets...)
		}
		return false, msg, failAllRefs(refUpdates, msg)
	}

	// Demux optional sideband-64k channel 0x01 / 0x03 or parse raw pkt-lines.
	demux := demuxReceivePackChannel1(body)
	scrubbedSidebandErr := ""
	if demux.sidebandErr != "" {
		scrubbedSidebandErr = inspection.NewRedactor(extraSecrets...).ScrubString(demux.sidebandErr)
	}
	if demux.parseErr != nil {
		msg := "malformed upstream receive-pack response"
		if scrubbedSidebandErr != "" {
			msg = scrubbedSidebandErr
		}
		return false, msg, failAllRefs(refUpdates, msg)
	}
	if scrubbedSidebandErr != "" {
		return false, scrubbedSidebandErr, failAllRefs(refUpdates, scrubbedSidebandErr)
	}
	if len(demux.reportBytes) == 0 {
		const msg = "upstream receive-pack returned empty status report"
		return false, msg, failAllRefs(refUpdates, msg)
	}

	rd := bytes.NewReader(demux.reportBytes)
	unpackSeen := false
	var pktParseErr error
	refStatusMap := make(map[string]RefResult, len(refUpdates))
	for {
		payload, flush, err := readPktLine(rd)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				pktParseErr = err
			}
			break
		}
		if flush {
			if rd.Len() == 0 {
				break
			}
			continue
		}
		line := strings.TrimRight(string(payload), "\r\n")
		if strings.HasPrefix(line, "unpack ") {
			unpackSeen = true
			rest := strings.TrimSpace(strings.TrimPrefix(line, "unpack "))
			if rest == "ok" {
				unpackOK = true
			} else {
				unpackOK = false
				unpackMsg = rest
			}
			continue
		}
		if ref, ok := strings.CutPrefix(line, "ok "); ok {
			ref = strings.TrimSpace(ref)
			refStatusMap[ref] = RefResult{RefName: ref, OK: true}
			continue
		}
		if rest, ok := strings.CutPrefix(line, "ng "); ok {
			ref, msg, _ := strings.Cut(rest, " ")
			ref = strings.TrimSpace(ref)
			refStatusMap[ref] = RefResult{RefName: ref, OK: false, Message: strings.TrimSpace(msg)}
		}
	}

	if pktParseErr != nil {
		unpackOK = false
		if unpackMsg == "" {
			unpackMsg = "malformed upstream report-status pkt-line"
		}
	}
	if !unpackSeen {
		unpackOK = false
		if unpackMsg == "" {
			unpackMsg = "upstream receive-pack response missing unpack status"
		}
	}
	if unpackMsg != "" {
		unpackMsg = inspection.NewRedactor(extraSecrets...).ScrubString(unpackMsg)
	}

	results = make([]RefResult, 0, len(refUpdates))
	for _, ru := range refUpdates {
		if !unpackOK {
			if rr, ok := refStatusMap[ru.RefName]; ok && !rr.OK {
				results = append(results, rr)
			} else {
				results = append(results, RefResult{RefName: ru.RefName, OK: false, Message: unpackMsg})
			}
			continue
		}
		if rr, ok := refStatusMap[ru.RefName]; ok {
			results = append(results, rr)
		} else {
			results = append(results, RefResult{RefName: ru.RefName, OK: true})
		}
	}
	return unpackOK, unpackMsg, results
}

type demuxedReceivePackBody struct {
	reportBytes []byte
	sawSideband bool
	sidebandErr string
	parseErr    error
}

func demuxReceivePackChannel1(raw []byte) demuxedReceivePackBody {
	if len(raw) == 0 {
		return demuxedReceivePackBody{
			parseErr: errors.New("empty upstream receive-pack response"),
		}
	}
	rd := bytes.NewReader(raw)
	var chan1 bytes.Buffer
	var errMsgs []string
	sawSideband := false
	for {
		payload, flush, err := readPktLine(rd)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return demuxedReceivePackBody{
				reportBytes: chan1.Bytes(),
				sawSideband: sawSideband,
				sidebandErr: strings.Join(errMsgs, "; "),
				parseErr:    err,
			}
		}
		if flush {
			if rd.Len() == 0 {
				break
			}
			continue
		}
		if len(payload) > 0 && (payload[0] == 0x01 || payload[0] == 0x02 || payload[0] == 0x03) {
			sawSideband = true
			switch payload[0] {
			case 0x01:
				chan1.Write(payload[1:])
			case 0x03:
				if msg := strings.TrimSpace(string(payload[1:])); msg != "" {
					errMsgs = append(errMsgs, msg)
				} else {
					errMsgs = append(errMsgs, "upstream sideband error")
				}
			}
			continue
		}
		if sawSideband {
			return demuxedReceivePackBody{
				reportBytes: chan1.Bytes(),
				sawSideband: true,
				sidebandErr: strings.Join(errMsgs, "; "),
				parseErr:    errors.New("unexpected non-sideband pkt-line in sideband stream"),
			}
		}
		return demuxedReceivePackBody{
			reportBytes: raw,
			sawSideband: false,
		}
	}
	return demuxedReceivePackBody{
		reportBytes: chan1.Bytes(),
		sawSideband: sawSideband,
		sidebandErr: strings.Join(errMsgs, "; "),
	}
}

func (h *PipelineReceivePackHandler) consumeApprovalReleaseTx(
	ctx context.Context,
	req ReceivePackRequest,
	sessionID uuid.UUID,
	repoIDPtr *uuid.UUID,
	manifestDigest string,
	hasLFS bool,
	lfsCount, lfsTotalBytes int64,
	pdID uuid.UUID,
	extraSecrets []string,
) (*uuid.UUID, *ReceivePackOutcome) {
	var consumedReleaseID *uuid.UUID
	consumeTime := h.nowFn().UTC()
	if err := h.store.WithTx(ctx, func(tx *persistence.Tx) error {
		consumed, txErr := tx.ConsumePushApprovalRelease(ctx, persistence.ConsumePushApprovalReleaseParams{
			PrincipalID:             req.Caller.Principal.ID,
			Destination:             req.Target.CanonicalDestination,
			PushManifestDigest:      manifestDigest,
			ConsumedAt:              consumeTime,
			ConsumedByPushSessionID: sessionID,
		})
		if txErr != nil {
			return txErr
		}
		relID := consumed.ID
		consumedReleaseID = &relID
		if _, txErr = tx.ApplyPushSessionPolicyDecision(ctx, persistence.ApplyPushSessionPolicyDecisionParams{
			ID:                sessionID,
			PolicyDecisionID:  pdID,
			ApprovalReleaseID: consumedReleaseID,
			Verdict:           domain.PolicyEffectAllow,
			Status:            domain.PushSessionStatusAllowed,
			UpdatedAt:         consumeTime,
		}); txErr != nil {
			return txErr
		}
		payloadBytes := h.buildAuditPayload(req, sessionID, repoIDPtr, manifestDigest, hasLFS, lfsCount, lfsTotalBytes, &pdID, consumedReleaseID, domain.PolicyEffectAllow, domain.PushSessionStatusAllowed, false, 0, "")
		_, txErr = h.auditSvc.AppendTx(ctx, tx, audit.AppendInput{
			EventType:    "push.approval_consumed",
			ActorID:      &req.Caller.Principal.ID,
			ResourceType: "push_session",
			ResourceID:   sessionID,
			Payload:      payloadBytes,
			CreatedAt:    consumeTime,
		})
		return txErr
	}); err != nil {
		h.metrics.IncPushApprovalRelease("rejected")
		code, safeMsg := safeGatewayError(err, extraSecrets...)
		if errors.Is(err, domain.ErrNotFound) {
			code = "APPROVAL_RELEASE_UNAVAILABLE"
			safeMsg = "push approval release was already consumed, expired, or revoked"
		}
		_, _ = h.store.CompletePushSession(ctx, persistence.CompletePushSessionParams{
			ID:                sessionID,
			Status:            domain.PushSessionStatusBlocked,
			UpstreamForwarded: false,
			UpstreamBytesSent: 0,
			ErrorCode:         code,
			ErrorMessage:      safeMsg,
			UpdatedAt:         h.nowFn().UTC(),
			CompletedAt:       h.nowFn().UTC(),
		})
		h.emitPushAudit(ctx, nil, "push.blocked", req, sessionID, repoIDPtr, manifestDigest, hasLFS, lfsCount, lfsTotalBytes, &pdID, nil, domain.PolicyEffectDeny, domain.PushSessionStatusBlocked, false, 0, code)
		h.writeSidebandLines(req.SidebandWriter, extraSecrets, "DENY: "+safeMsg)
		return nil, &ReceivePackOutcome{
			SessionID:          sessionID,
			Status:             domain.PushSessionStatusBlocked,
			Effect:             domain.PolicyEffectDeny,
			UpstreamForwarded:  false,
			UpstreamBytesSent:  0,
			UnpackOK:           true,
			RefResults:         failAllRefs(req.RefUpdates, safeMsg),
			PushManifestDigest: manifestDigest,
			ErrorCode:          code,
			ErrorMessage:       safeMsg,
			HTTPStatus:         0,
		}
	}
	h.metrics.IncPushApprovalRelease("consumed")
	return consumedReleaseID, nil
}

// shouldAllowMissingLFSWhenApproved determines whether an approved ENFORCE_BLOCK push may
// skip HTTP 404 (un-uploaded) LFS objects during upstream verification.
//
// Predicate (fail-closed by default):
//   - Requires approvalUsable == true and len(lfsObjects) > 0.
//   - When Stage C evaluated REQUIRE_APPROVAL: at least one REQUIRE_APPROVAL reason matched and
//     EVERY matched REQUIRE_APPROVAL reason is an LFS-gating rule (referencing push.has_lfs,
//     push.lfs_total_bytes, or push.lfs_object_count without non-LFS IP/assessment signals).
//   - When Stage C evaluated ALLOW (custom CEL using push.approval_release_present): the
//     originating policy decision referenced by relRow.PolicyDecisionID must have had
//     REQUIRE_APPROVAL reasons that were ALL LFS-gating rules (or, if unavailable, the matched
//     ALLOW rule itself gates on both LFS and push.approval_release_present).
func (h *PipelineReceivePackHandler) shouldAllowMissingLFSWhenApproved(
	ctx context.Context,
	orgBundles, repoBundles []persistedCompiledBundle,
	evalOutcome composedPushEvalOutcome,
	relRow persistence.PushApprovalReleaseRow,
	approvalUsable bool,
	lfsObjects []domain.PushLFSObject,
) bool {
	if !approvalUsable || len(lfsObjects) == 0 {
		return false
	}
	ruleMap := indexCompiledPushRules(orgBundles, repoBundles)

	if evalOutcome.result.Effect == domain.PolicyEffectRequireApproval {
		return allApprovalReasonsAreLFSOnly(evalOutcome.result.Reasons, ruleMap)
	}
	if evalOutcome.result.Effect == domain.PolicyEffectAllow {
		if h.store != nil && relRow.PolicyDecisionID != uuid.Nil {
			if priorRow, err := h.store.GetPolicyDecisionByID(ctx, relRow.PolicyDecisionID); err == nil {
				priorDec := priorRow.ToDomain()
				if priorDec.Effect == domain.PolicyEffectRequireApproval && len(priorDec.Reasons) > 0 {
					return allApprovalReasonsAreLFSOnly(priorDec.Reasons, ruleMap)
				}
				return false
			}
		}
		for _, r := range evalOutcome.result.Reasons {
			if r.Effect != domain.PolicyEffectAllow {
				continue
			}
			for _, spec := range ruleMap[r.RuleID] {
				if spec != nil && strings.Contains(spec.When, "push.approval_release_present") && isLFSPolicyRule(r.RuleID, spec) {
					return true
				}
			}
		}
	}
	return false
}

func indexCompiledPushRules(orgBundles, repoBundles []persistedCompiledBundle) map[string][]*policy.Rule {
	out := make(map[string][]*policy.Rule)
	for _, b := range orgBundles {
		if b.compiled == nil {
			continue
		}
		for i := range b.compiled.Rules {
			spec := b.compiled.Rules[i].Spec
			out[spec.ID] = append(out[spec.ID], &spec)
		}
	}
	for _, b := range repoBundles {
		if b.compiled == nil {
			continue
		}
		for i := range b.compiled.Rules {
			spec := b.compiled.Rules[i].Spec
			out[spec.ID] = append(out[spec.ID], &spec)
		}
	}
	return out
}

func allApprovalReasonsAreLFSOnly(reasons []domain.PolicyReason, ruleMap map[string][]*policy.Rule) bool {
	sawRequireApproval := false
	for _, r := range reasons {
		if r.Effect != domain.PolicyEffectRequireApproval {
			continue
		}
		sawRequireApproval = true
		specs := ruleMap[r.RuleID]
		if len(specs) == 0 {
			if !isLFSPolicyRule(r.RuleID, nil) {
				return false
			}
			continue
		}
		for _, spec := range specs {
			if !isLFSPolicyRule(r.RuleID, spec) {
				return false
			}
		}
	}
	return sawRequireApproval
}

func isLFSPolicyRule(ruleID string, ruleSpec *policy.Rule) bool {
	if ruleID == "" || ruleID == "defaults.effect" || ruleID == "bundle.missing" || ruleID == "policy.eval_error" {
		return false
	}
	if ruleSpec != nil {
		when := ruleSpec.When
		hasLFSExpr := strings.Contains(when, "push.has_lfs") ||
			strings.Contains(when, "push.lfs_total_bytes") ||
			strings.Contains(when, "push.lfs_object_count")
		hasNonLFSReviewSignal := strings.Contains(when, "confidential_ip_matches") ||
			strings.Contains(when, "ip_exact_matches") ||
			strings.Contains(when, "ip_winnow_matches") ||
			strings.Contains(when, "assessment.")
		return hasLFSExpr && !hasNonLFSReviewSignal
	}
	id := strings.ToLower(strings.TrimSpace(ruleID))
	return strings.HasPrefix(id, "push.lfs.") || strings.Contains(id, ".lfs.") || strings.HasPrefix(id, "lfs.")
}

func statusForPolicyEffect(mode domain.EgressMode, effect domain.PolicyEffect, infraFailed bool) domain.PushSessionStatus {
	if mode == domain.EgressModePassiveAudit {
		if effect != domain.PolicyEffectAllow || infraFailed {
			return domain.PushSessionStatusObservedWouldBlock
		}
		return domain.PushSessionStatusAllowed
	}
	switch effect {
	case domain.PolicyEffectAllow:
		return domain.PushSessionStatusAllowed
	case domain.PolicyEffectRequireApproval:
		return domain.PushSessionStatusApprovalRequired
	case domain.PolicyEffectQuarantine:
		return domain.PushSessionStatusQuarantined
	default:
		return domain.PushSessionStatusBlocked
	}
}

func primaryPolicyReasonMessage(res policy.EvalResult) string {
	for _, r := range res.Reasons {
		if r.Effect == res.Effect && strings.TrimSpace(r.Message) != "" {
			return r.Message
		}
	}
	for _, r := range res.Reasons {
		if strings.TrimSpace(r.Message) != "" {
			return r.Message
		}
	}
	return fmt.Sprintf("push policy effect: %s", res.Effect)
}

func failAllRefs(refUpdates []quarantine.RefUpdate, msg string) []RefResult {
	out := make([]RefResult, 0, len(refUpdates))
	for _, ru := range refUpdates {
		out = append(out, RefResult{
			RefName: ru.RefName,
			OK:      false,
			Message: msg,
		})
	}
	return out
}

func nonNilLFSObjects(in []domain.PushLFSObject) []domain.PushLFSObject {
	if len(in) == 0 {
		return []domain.PushLFSObject{}
	}
	return in
}

func safeGatewayError(err error, secrets ...string) (string, string) {
	if err == nil {
		return "", ""
	}
	code := "GATEWAY_ERROR"
	msg := err.Error()
	var domErr *domain.DomainError
	if errors.As(err, &domErr) {
		code = domErr.Code()
		msg = domErr.Message
	}
	if strings.TrimSpace(msg) == "" {
		msg = code
	}
	redactor := inspection.NewRedactor(secrets...)
	return code, redactor.ScrubString(msg)
}

func spoolPassivePackReader(r io.Reader, maxBytes int64) (*os.File, int64, error) {
	f, err := os.CreateTemp("", "custodian-passive-pack-*")
	if err != nil {
		return nil, 0, domain.WrapError(domain.ErrInternal, "PASSIVE_SPOOL_FAILED", "failed creating passive pack spool file", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			name := f.Name()
			_ = f.Close()
			_ = os.Remove(name)
		}
	}()
	n, err := io.Copy(f, io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, 0, err
	}
	if n > maxBytes {
		return nil, 0, errStreamLimitExceeded
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, 0, domain.WrapError(domain.ErrInternal, "PASSIVE_SPOOL_FAILED", "failed rewinding passive pack spool file", err)
	}
	cleanup = false
	return f, n, nil
}

func (h *PipelineReceivePackHandler) forwardPassiveAuditRawPack(
	ctx context.Context,
	req ReceivePackRequest,
	sessionID uuid.UUID,
	repoIDPtr *uuid.UUID,
	transport domain.PushTransport,
	egressMode domain.EgressMode,
	delivery domain.PassiveAuditDelivery,
	packReader io.Reader,
	packBytes int64,
	infraErrCode, infraReason string,
	extraSecrets []string,
) (ReceivePackOutcome, error) {
	effectiveEffect := domain.PolicyEffectDeny
	h.metrics.IncPushPassiveAuditWouldBlock(string(delivery), string(effectiveEffect))
	if delivery == domain.PassiveAuditDeliveryInlineWarn {
		reason := infraReason
		if reason == "" {
			reason = "baseline fetch failed in PASSIVE_AUDIT"
		}
		h.writeSidebandLines(req.SidebandWriter, extraSecrets,
			fmt.Sprintf("PASSIVE_AUDIT WARNING (%s): push would be blocked under ENFORCE_BLOCK (%s)", effectiveEffect, reason),
		)
	}

	if strings.TrimSpace(req.UpstreamToken) == "" {
		const code = "UPSTREAM_AUTH_UNAVAILABLE"
		const safeMsg = "no upstream write credential available for target destination"
		_, _ = h.store.CompletePushSession(ctx, persistence.CompletePushSessionParams{
			ID:                sessionID,
			Status:            domain.PushSessionStatusObservedWouldBlock,
			UpstreamForwarded: false,
			UpstreamBytesSent: 0,
			ErrorCode:         code,
			ErrorMessage:      safeMsg,
			UpdatedAt:         h.nowFn().UTC(),
			CompletedAt:       h.nowFn().UTC(),
		})
		h.emitPushAudit(ctx, nil, "push.failed", req, sessionID, repoIDPtr, "", false, 0, 0, nil, nil, effectiveEffect, domain.PushSessionStatusObservedWouldBlock, false, 0, code)
		h.writeSidebandLines(req.SidebandWriter, extraSecrets, "ERROR: "+safeMsg)
		return ReceivePackOutcome{
			SessionID:         sessionID,
			Status:            domain.PushSessionStatusObservedWouldBlock,
			Effect:            effectiveEffect,
			UpstreamForwarded: false,
			UpstreamBytesSent: 0,
			UnpackOK:          true,
			RefResults:        failAllRefs(req.RefUpdates, safeMsg),
			ErrorCode:         code,
			ErrorMessage:      safeMsg,
			HTTPStatus:        0,
		}, nil
	}

	_ = h.updatePushSessionStatus(ctx, sessionID, domain.PushSessionStatusForwarding)

	var hdrBuf bytes.Buffer
	for i, ru := range req.RefUpdates {
		if i == 0 {
			_ = writePktLine(&hdrBuf, []byte(fmt.Sprintf("%s %s %s\x00report-status\n", ru.OldOID, ru.NewOID, ru.RefName)))
		} else {
			_ = writePktLine(&hdrBuf, []byte(fmt.Sprintf("%s %s %s\n", ru.OldOID, ru.NewOID, ru.RefName)))
		}
	}
	_ = writeFlushPkt(&hdrBuf)

	var bodyReader io.Reader = &hdrBuf
	if packBytes > 0 && packReader != nil {
		bodyReader = io.MultiReader(&hdrBuf, packReader)
	}

	forwardStart := h.nowFn().UTC()
	upStatus, upBody, bytesSent, upErr := h.upstream.ReceivePack(ctx, req.Target.OwnerRepo, req.UpstreamToken, bodyReader)
	h.metrics.ObservePushPhase(string(transport), string(egressMode), "forward", h.nowFn().UTC().Sub(forwardStart))
	if bytesSent > 0 {
		h.metrics.AddPushUpstreamBytes(string(egressMode), "receive_pack", bytesSent)
	}

	upstreamForwarded := upErr == nil && bytesSent > 0
	upUnpackOK, upUnpackMsg, refResults := parseUpstreamReceivePackOutcome(upStatus, upBody, upErr, req.RefUpdates, extraSecrets)

	allRefsOK := upUnpackOK && upErr == nil && upStatus == http.StatusOK
	for _, rr := range refResults {
		if !rr.OK {
			allRefsOK = false
			break
		}
	}

	finalStatus := domain.PushSessionStatusObservedWouldBlock
	auditEventType := "push.observed_would_block"
	var errCode, errMsg string
	if !allRefsOK {
		finalStatus = domain.PushSessionStatusFailed
		auditEventType = "push.failed"
		errCode = "UPSTREAM_RECEIVE_PACK_FAILED"
		errMsg = upUnpackMsg
		if errMsg == "" {
			errMsg = fmt.Sprintf("upstream receive-pack rejected push (status %d)", upStatus)
		}
	}

	_, _ = h.store.CompletePushSession(ctx, persistence.CompletePushSessionParams{
		ID:                sessionID,
		Status:            finalStatus,
		UpstreamForwarded: upstreamForwarded,
		UpstreamBytesSent: bytesSent,
		ErrorCode:         errCode,
		ErrorMessage:      errMsg,
		UpdatedAt:         h.nowFn().UTC(),
		CompletedAt:       h.nowFn().UTC(),
	})

	auditErrCode := errCode
	if auditErrCode == "" {
		auditErrCode = infraErrCode
	}
	h.emitPushAudit(ctx, nil, auditEventType, req, sessionID, repoIDPtr, "", false, 0, 0, nil, nil, effectiveEffect, finalStatus, upstreamForwarded, bytesSent, auditErrCode)

	if allRefsOK {
		h.writeSidebandLines(req.SidebandWriter, extraSecrets,
			fmt.Sprintf("PASSIVE_AUDIT OBSERVED_WOULD_BLOCK: push forwarded upstream (push_session_id=%s)", sessionID.String()),
		)
	} else {
		h.writeSidebandLines(req.SidebandWriter, extraSecrets, "ERROR: "+errMsg)
	}

	return ReceivePackOutcome{
		SessionID:          sessionID,
		Status:             finalStatus,
		Effect:             effectiveEffect,
		UpstreamForwarded:  upstreamForwarded,
		UpstreamBytesSent:  bytesSent,
		UpstreamStatusLine: fmt.Sprintf("HTTP %d", upStatus),
		UnpackOK:           upUnpackOK,
		UnpackMessage:      upUnpackMsg,
		RefResults:         refResults,
		ErrorCode:          errCode,
		ErrorMessage:       errMsg,
		HTTPStatus:         0,
	}, nil
}
