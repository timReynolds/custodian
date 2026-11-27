package domain

import (
	"encoding/json"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestDomainImportsLayer0Only(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(".", name), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s): %v", name, err)
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if p == "github.com/google/uuid" {
				continue
			}
			// Stdlib packages do not contain a dot in the first path segment.
			firstSeg := strings.Split(p, "/")[0]
			if strings.Contains(firstSeg, ".") {
				t.Fatalf("Layer 0 violation in %s: forbidden import %q", name, p)
			}
		}
	}
}

func TestEnumsIsValid(t *testing.T) {
	if !PrincipalKindHuman.IsValid() || !PrincipalKindAgent.IsValid() || !PrincipalKindService.IsValid() || PrincipalKind("ROBOT").IsValid() {
		t.Fatal("PrincipalKind.IsValid failed")
	}
	if !ClassificationPublic.IsValid() || !ClassificationRestricted.IsValid() || Classification("TOP_SECRET").IsValid() {
		t.Fatal("Classification.IsValid failed")
	}
	if !WorkspaceStatusReady.IsValid() || WorkspaceStatus("UNKNOWN").IsValid() || !WorkspaceStatusClosed.IsTerminal() || WorkspaceStatusReady.IsTerminal() {
		t.Fatal("WorkspaceStatus methods failed")
	}
	if !ArtifactKindWorkspaceSource.IsValid() || !ArtifactKindPublicationManifest.IsValid() || !ArtifactKindGitPushBundle.IsValid() || ArtifactKind("BOGUS").IsValid() {
		t.Fatal("ArtifactKind.IsValid failed")
	}
	if !PolicyStageIngress.IsValid() || !PolicyStageEgress.IsValid() || !PolicyStagePushEgress.IsValid() || PolicyStage("BOGUS").IsValid() {
		t.Fatal("PolicyStage.IsValid failed")
	}
	if !EgressModePassiveAudit.IsValid() || !EgressModeEnforceBlock.IsValid() || !EgressModeEnforcePR.IsValid() || EgressMode("BOGUS").IsValid() {
		t.Fatal("EgressMode.IsValid failed")
	}
	if !PassiveAuditDeliveryAsync.IsValid() || !PassiveAuditDeliveryInlineWarn.IsValid() || PassiveAuditDelivery("BOGUS").IsValid() {
		t.Fatal("PassiveAuditDelivery.IsValid failed")
	}
	if !PushTransportHTTPS.IsValid() || !PushTransportSSH.IsValid() || PushTransport("FTP").IsValid() {
		t.Fatal("PushTransport.IsValid failed")
	}
	for _, st := range []PushSessionStatus{
		PushSessionStatusReceived, PushSessionStatusUnpacking, PushSessionStatusQuarantined,
		PushSessionStatusInspecting, PushSessionStatusEvaluating, PushSessionStatusAllowed,
		PushSessionStatusBlocked, PushSessionStatusApprovalRequired, PushSessionStatusForwarding,
		PushSessionStatusCompleted, PushSessionStatusObservedWouldBlock, PushSessionStatusFailed,
	} {
		if !st.IsValid() {
			t.Fatalf("expected PushSessionStatus %s to be valid", st)
		}
	}
	if PushSessionStatus("BOGUS").IsValid() {
		t.Fatal("bogus PushSessionStatus should be invalid")
	}
	if !PushSessionStatusCompleted.IsTerminal() || !PushSessionStatusBlocked.IsTerminal() || !PushSessionStatusQuarantined.IsTerminal() || !PushSessionStatusObservedWouldBlock.IsTerminal() || !PushSessionStatusFailed.IsTerminal() {
		t.Fatal("expected terminal PushSessionStatus values")
	}
	if PushSessionStatusReceived.IsTerminal() || PushSessionStatusForwarding.IsTerminal() || PushSessionStatusApprovalRequired.IsTerminal() {
		t.Fatal("expected non-terminal PushSessionStatus values")
	}
	if !IPCorpusStatusPending.IsValid() || !IPCorpusStatusIndexing.IsValid() || !IPCorpusStatusReady.IsValid() || !IPCorpusStatusFailed.IsValid() || IPCorpusStatus("BOGUS").IsValid() {
		t.Fatal("IPCorpusStatus.IsValid failed")
	}
	if !FingerprintLayerL1ExactChunk.IsValid() || !FingerprintLayerL2WinnowKGram.IsValid() || !FingerprintLayerL3HeaderMarker.IsValid() || FingerprintLayer("L9").IsValid() {
		t.Fatal("FingerprintLayer.IsValid failed")
	}
	if !ProposalStatusPendingApproval.CanApprove() || ProposalStatusApproved.CanApprove() {
		t.Fatal("ProposalStatus.CanApprove failed")
	}
	if !ProposalStatusApproved.CanPublish() || ProposalStatusPendingApproval.CanPublish() {
		t.Fatal("ProposalStatus.CanPublish failed")
	}
	if !ProposalStatusPublished.IsTerminal() || ProposalStatusEvaluating.IsTerminal() || !ProposalStatusCaptured.IsValid() || ProposalStatus("NOPE").IsValid() {
		t.Fatal("ProposalStatus methods failed")
	}
	if !SeverityCritical.IsValid() || Severity("EXTREME").IsValid() {
		t.Fatal("Severity.IsValid failed")
	}
	if !ScanStatusCompleted.IsValid() || ScanStatus("BOGUS").IsValid() {
		t.Fatal("ScanStatus.IsValid failed")
	}
	if !AssessmentStatusComplete.IsValid() || !AssessmentStatusNotRequired.IsValid() || AssessmentStatus("BOGUS").IsValid() {
		t.Fatal("AssessmentStatus.IsValid failed")
	}
	if !RiskLevelNone.IsValid() || RiskLevel("BOGUS").IsValid() {
		t.Fatal("RiskLevel.IsValid failed")
	}
	if !DispositionClear.IsValid() || !DispositionNotRequired.IsValid() || Disposition("BOGUS").IsValid() {
		t.Fatal("Disposition.IsValid failed")
	}
	if !PolicyScopeOrg.IsValid() || !PolicyScopeRepo.IsValid() || PolicyScope("GLOBAL").IsValid() {
		t.Fatal("PolicyScope.IsValid failed")
	}
	if !ApprovalDecisionApprove.IsValid() || !ApprovalDecisionReject.IsValid() || ApprovalDecision("MAYBE").IsValid() {
		t.Fatal("ApprovalDecision.IsValid failed")
	}
	if !PublicationStatusPublished.IsValid() || PublicationStatus("BOGUS").IsValid() {
		t.Fatal("PublicationStatus.IsValid failed")
	}
	if !OperationStatusPending.IsValid() || !OperationStatusSucceeded.IsTerminal() || OperationStatusRunning.IsTerminal() || OperationStatus("BOGUS").IsValid() {
		t.Fatal("OperationStatus methods failed")
	}
}

func TestPolicyEffectPrecedence(t *testing.T) {
	effects := []PolicyEffect{
		PolicyEffectAllow,
		PolicyEffectRequireApproval,
		PolicyEffectRequireRemediation,
		PolicyEffectQuarantine,
		PolicyEffectDeny,
	}
	for i, a := range effects {
		for j, b := range effects {
			got := a.MoreRestrictive(b)
			want := a
			if j > i {
				want = b
			}
			if got != want {
				t.Fatalf("%s.MoreRestrictive(%s) = %s, want %s", a, b, got, want)
			}
		}
	}
	// Unknown fails closed to DENY
	if got := PolicyEffectAllow.MoreRestrictive(PolicyEffect("INVALID")); got != PolicyEffectDeny {
		t.Fatalf("unknown effect did not fail closed to DENY: got %s", got)
	}
	if !PolicyEffectDeny.BlocksPublication() || !PolicyEffectQuarantine.BlocksPublication() || !PolicyEffectRequireRemediation.BlocksPublication() {
		t.Fatal("expected DENY/QUARANTINE/REQUIRE_REMEDIATION to block publication")
	}
	if PolicyEffectRequireApproval.BlocksPublication() || PolicyEffectAllow.BlocksPublication() {
		t.Fatal("REQUIRE_APPROVAL and ALLOW should not block publication at policy effect level")
	}
}

func TestScanRunAndFindingRedaction(t *testing.T) {
	clean := ScanRun{
		Status:   ScanStatusCompleted,
		Coverage: ScanCoverage{FilesExamined: 12, FilesSkipped: 0, Complete: true},
	}
	if !clean.IsCleanComplete() {
		t.Fatal("expected clean complete scan")
	}
	skipped := ScanRun{
		Status:   ScanStatusCompleted,
		Coverage: ScanCoverage{FilesExamined: 11, FilesSkipped: 1, Complete: false},
	}
	if skipped.IsCleanComplete() {
		t.Fatal("scan with FilesSkipped > 0 must not report IsCleanComplete")
	}
	failed := ScanRun{
		Status:   ScanStatusFailed,
		Coverage: ScanCoverage{FilesExamined: 12, FilesSkipped: 0, Complete: true},
	}
	if failed.IsCleanComplete() {
		t.Fatal("FAILED scan must not report IsCleanComplete")
	}

	safeFinding := Finding{
		Category: "SECRET",
		Redacted: true,
		Metadata: map[string]any{"detector": "gitleaks", "entropy": 4.2},
	}
	if err := safeFinding.ValidateRedacted(); err != nil {
		t.Fatalf("ValidateRedacted(safe) unexpected err: %v", err)
	}

	unredacted := Finding{Category: "SECRET", Redacted: false}
	if err := unredacted.ValidateRedacted(); !errors.Is(err, ErrUnprocessable) {
		t.Fatalf("unredacted secret expected ErrUnprocessable, got %v", err)
	}

	leakedMeta := Finding{
		Category: "LICENCE",
		Redacted: true,
		Metadata: map[string]any{"nested": map[string]any{"raw_secret": "ghp_1234"}},
	}
	if err := leakedMeta.ValidateRedacted(); !errors.Is(err, ErrUnprocessable) {
		t.Fatalf("forbidden metadata key expected ErrUnprocessable, got %v", err)
	}

	type secretWrapper struct {
		Inner map[string]string
	}
	type secretFieldStruct struct {
		MatchRaw string `json:"match_raw"`
	}
	var nilMap map[string]string
	var nilPtr *secretWrapper

	typedCases := []struct {
		name string
		meta map[string]any
	}{
		{
			name: "map[string]string",
			meta: map[string]any{"nested": map[string]string{"raw_secret": "ghp_leaked12345"}},
		},
		{
			name: "[]map[string]any",
			meta: map[string]any{"items": []map[string]any{{"secret": "ghp_leaked12345"}}},
		},
		{
			name: "[]map[string]string",
			meta: map[string]any{"items": []map[string]string{{"token": "ghp_leaked12345"}}},
		},
		{
			name: "array of map[string]string",
			meta: map[string]any{"items": [1]map[string]string{{"password": "hunter2"}}},
		},
		{
			name: "pointer to map[string]string",
			meta: map[string]any{"ptr": &map[string]string{"private_key": "pem"}},
		},
		{
			name: "struct wrapping map[string]string",
			meta: map[string]any{"wrapped": secretWrapper{Inner: map[string]string{"credential": "cred"}}},
		},
		{
			name: "pointer to struct wrapping secret",
			meta: map[string]any{"wrapped_ptr": &secretWrapper{Inner: map[string]string{"raw_secret": "x"}}},
		},
		{
			name: "struct with json tag match_raw",
			meta: map[string]any{"struct_field": secretFieldStruct{MatchRaw: "raw"}},
		},
		{
			name: "map[any]string non-string key",
			meta: map[string]any{"any_key_map": map[any]string{"secret": "x"}},
		},
	}
	for _, tc := range typedCases {
		f := Finding{Category: "SECRET", Redacted: true, Metadata: tc.meta}
		if err := f.ValidateRedacted(); !errors.Is(err, ErrUnprocessable) {
			t.Fatalf("%s: expected ErrUnprocessable, got %v", tc.name, err)
		}
	}

	safeTyped := Finding{
		Category: "SECRET",
		Redacted: true,
		Metadata: map[string]any{
			"tags":     map[string]string{"detector": "gitleaks"},
			"items":    []map[string]string{{"rule": "aws-access-token"}},
			"nil_map":  nilMap,
			"nil_ptr":  nilPtr,
			"ts":       time.Now().UTC(),
			"safe_box": secretWrapper{Inner: map[string]string{"fingerprint": "abc"}},
		},
	}
	if err := safeTyped.ValidateRedacted(); err != nil {
		t.Fatalf("safe typed metadata returned unexpected err: %v", err)
	}
}

func TestValidateRedacted_CyclicSlicesAndEmbeddedUnexportedStructs(t *testing.T) {
	// 1. Self-referential safe cyclic slice must not overflow stack and must pass.
	safeCyclicSlice := make([]any, 1)
	safeCyclicSlice[0] = safeCyclicSlice
	if err := (Finding{
		Category: "SECRET",
		Redacted: true,
		Metadata: map[string]any{"cycle": safeCyclicSlice},
	}).ValidateRedacted(); err != nil {
		t.Fatalf("safe cyclic slice returned unexpected err: %v", err)
	}

	// 2. Cyclic slice containing a forbidden metadata key must return ErrUnprocessable without overflow.
	secretCyclicSlice := make([]any, 2)
	secretCyclicSlice[0] = secretCyclicSlice
	secretCyclicSlice[1] = map[string]string{"raw_secret": "x"}
	if err := (Finding{
		Category: "SECRET",
		Redacted: true,
		Metadata: map[string]any{"cycle": secretCyclicSlice},
	}).ValidateRedacted(); !errors.Is(err, ErrUnprocessable) {
		t.Fatalf("cyclic slice with secret expected ErrUnprocessable, got %v", err)
	}

	// 3. Sub-slice cycle with different view length must also terminate cleanly.
	subSlice := make([]any, 2)
	subSlice[0] = subSlice[:1]
	subSlice[1] = map[string]string{"token": "leak"}
	if err := (Finding{
		Category: "SECRET",
		Redacted: true,
		Metadata: map[string]any{"sub_cycle": subSlice},
	}).ValidateRedacted(); !errors.Is(err, ErrUnprocessable) {
		t.Fatalf("sub-slice cycle with secret expected ErrUnprocessable, got %v", err)
	}

	// 4. Embedded unexported struct with promoted exported json:"raw_secret" must return ErrUnprocessable.
	type hiddenInner struct {
		RawSecret string `json:"raw_secret"`
	}
	type outerWithEmbeddedUnexported struct {
		hiddenInner
	}
	type outerWithEmbeddedUnexportedPtr struct {
		*hiddenInner
	}
	if err := (Finding{
		Category: "SECRET",
		Redacted: true,
		Metadata: map[string]any{
			"embedded": outerWithEmbeddedUnexported{hiddenInner: hiddenInner{RawSecret: "ghp_embedded_leak"}},
		},
	}).ValidateRedacted(); !errors.Is(err, ErrUnprocessable) {
		t.Fatalf("embedded unexported struct expected ErrUnprocessable, got %v", err)
	}
	if err := (Finding{
		Category: "SECRET",
		Redacted: true,
		Metadata: map[string]any{
			"embedded_ptr": outerWithEmbeddedUnexportedPtr{hiddenInner: &hiddenInner{RawSecret: "ghp_embedded_ptr_leak"}},
		},
	}).ValidateRedacted(); !errors.Is(err, ErrUnprocessable) {
		t.Fatalf("embedded unexported struct pointer expected ErrUnprocessable, got %v", err)
	}

	// 5. Unexported non-embedded fields must be ignored (matching encoding/json), while diamond DAGs are still fully traversed.
	type safeHiddenInner struct {
		Safe      string `json:"safe"`
		rawSecret string // unexported non-embedded field: ignored by encoding/json
	}
	type outerSafe struct {
		safeHiddenInner
		secret string // unexported non-embedded field: ignored by encoding/json
	}
	sharedSafeSlice := []any{map[string]string{"rule": "gitleaks"}}
	sharedSafeMap := map[string]string{"detector": "semgrep"}
	sharedSafeStruct := &outerSafe{
		safeHiddenInner: safeHiddenInner{Safe: "ok", rawSecret: "ignored"},
		secret:          "ignored",
	}
	if err := (Finding{
		Category: "SECRET",
		Redacted: true,
		Metadata: map[string]any{
			"s1": sharedSafeSlice,
			"s2": sharedSafeSlice,
			"m1": sharedSafeMap,
			"m2": sharedSafeMap,
			"p1": sharedSafeStruct,
			"p2": sharedSafeStruct,
		},
	}).ValidateRedacted(); err != nil {
		t.Fatalf("diamond DAG with unexported non-embedded fields returned unexpected err: %v", err)
	}

	// 6. Pointer to struct vs pointer to its first field (same uintptr, different types) must not collide.
	type firstFieldSecret struct {
		First map[string]string
	}
	ffs := firstFieldSecret{First: map[string]string{"raw_secret": "x"}}
	if err := (Finding{
		Category: "SECRET",
		Redacted: true,
		Metadata: map[string]any{
			"outer": &ffs,
			"inner": &ffs.First,
		},
	}).ValidateRedacted(); !errors.Is(err, ErrUnprocessable) {
		t.Fatalf("struct/first-field pointer pair expected ErrUnprocessable, got %v", err)
	}
}

type testValMarshaler struct {
	payload []byte
	err     error
}

func (m testValMarshaler) MarshalJSON() ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.payload, nil
}

type testPtrMarshaler struct {
	Safe    string `json:"safe,omitempty"`
	payload []byte
	err     error
}

func (m *testPtrMarshaler) MarshalJSON() ([]byte, error) {
	// Intentionally dereference m so calling MarshalJSON on a typed nil pointer would panic.
	if m.err != nil {
		return nil, m.err
	}
	return m.payload, nil
}

type testPtrMarshalerWithExportedSecret struct {
	RawSecret string `json:"raw_secret"`
}

func (m *testPtrMarshalerWithExportedSecret) MarshalJSON() ([]byte, error) {
	return []byte(`{"safe":"ok"}`), nil
}

func TestValidateRedacted_RawMessageAndJSONMarshaler(t *testing.T) {
	type rawWrapper struct {
		Detail json.RawMessage `json:"detail"`
	}
	type hiddenRawEmbedded struct {
		Detail json.RawMessage `json:"detail"`
	}
	type outerHiddenRawEmbedded struct {
		hiddenRawEmbedded
	}
	type ptrMarshalerStruct struct {
		PM testPtrMarshaler `json:"pm"`
	}
	type customBytes []byte

	rejectedCases := []struct {
		name string
		meta map[string]any
	}{
		{
			name: "raw_message_nested_secret",
			meta: map[string]any{"payload": json.RawMessage(`{"nested":{"raw_secret":"ghp_rawmessage_leak"}}`)},
		},
		{
			name: "raw_message_array_password",
			meta: map[string]any{"payload": json.RawMessage(`[{"password":"p"}]`)},
		},
		{
			name: "raw_message_unicode_escaped_key",
			meta: map[string]any{"payload": json.RawMessage(`{"\u0072aw_secret":"ghp_unicode"}`)},
		},
		{
			name: "raw_message_malformed",
			meta: map[string]any{"payload": json.RawMessage(`{bad`)},
		},
		{
			name: "raw_message_empty_string",
			meta: map[string]any{"payload": json.RawMessage("")},
		},
		{
			name: "raw_message_empty_non_nil_slice",
			meta: map[string]any{"payload": json.RawMessage{}},
		},
		{
			name: "raw_message_trailing_json_with_secret",
			meta: map[string]any{"payload": json.RawMessage(`{"a":1}{"raw_secret":"x"}`)},
		},
		{
			name: "raw_message_trailing_garbage",
			meta: map[string]any{"payload": json.RawMessage(`{"a":1} trailing`)},
		},
		{
			name: "raw_message_in_struct_field",
			meta: map[string]any{"w": rawWrapper{Detail: json.RawMessage(`[{"password":"p"}]`)}},
		},
		{
			name: "raw_message_in_unexported_embedded_struct",
			meta: map[string]any{"w": outerHiddenRawEmbedded{hiddenRawEmbedded: hiddenRawEmbedded{Detail: json.RawMessage(`{"token":"t"}`)}}},
		},
		{
			name: "value_marshaler_secret",
			meta: map[string]any{"vm": testValMarshaler{payload: []byte(`{"raw_secret":"ghp_val_leak"}`)}},
		},
		{
			name: "value_marshaler_error_fails_closed",
			meta: map[string]any{"vm": testValMarshaler{err: errors.New("marshal failed")}},
		},
		{
			name: "value_marshaler_malformed_fails_closed",
			meta: map[string]any{"vm": testValMarshaler{payload: []byte(`{bad`)}},
		},
		{
			name: "value_marshaler_trailing_fails_closed",
			meta: map[string]any{"vm": testValMarshaler{payload: []byte(`{"ok":1}{"secret":"x"}`)}},
		},
		{
			name: "pointer_marshaler_in_map_secret",
			meta: map[string]any{"pm": &testPtrMarshaler{payload: []byte(`{"raw_secret":"ghp_ptr_leak"}`)}},
		},
		{
			name: "pointer_marshaler_in_addressable_struct_field",
			meta: map[string]any{"s": &ptrMarshalerStruct{PM: testPtrMarshaler{payload: []byte(`{"private_key":"pem"}`)}}},
		},
		{
			name: "pointer_marshaler_in_slice_element",
			meta: map[string]any{"items": []testPtrMarshaler{{payload: []byte(`{"credential":"cred"}`)}}},
		},
		{
			name: "pointer_marshaler_error_fails_closed",
			meta: map[string]any{"pm": &testPtrMarshaler{err: errors.New("ptr marshal failed")}},
		},
		{
			name: "non_addressable_ptr_marshaler_falls_back_to_struct_fields",
			meta: map[string]any{"pm_val": testPtrMarshalerWithExportedSecret{RawSecret: "ghp_fallback_leak"}},
		},
	}

	for _, tc := range rejectedCases {
		t.Run(tc.name, func(t *testing.T) {
			f := Finding{Category: "SECRET", Redacted: true, Metadata: tc.meta}
			if err := f.ValidateRedacted(); !errors.Is(err, ErrUnprocessable) {
				t.Fatalf("%s: expected ErrUnprocessable, got %v", tc.name, err)
			}
		})
	}

	var nilRawPtr *json.RawMessage
	var nilRaw json.RawMessage
	var nilPtrMarshaler *testPtrMarshaler
	var nilTimePtr *time.Time
	now := time.Now().UTC()

	allowedMeta := map[string]any{
		"raw_safe":             json.RawMessage(`{"rule":"ok","count":42}`),
		"raw_null_literal":     json.RawMessage(`null`),
		"raw_nil":              nilRaw,
		"raw_nil_ptr":          nilRawPtr,
		"raw_ptr_to_nil":       &nilRaw,
		"raw_struct_safe":      rawWrapper{Detail: json.RawMessage(`{"rule":"ok"}`)},
		"val_marshaler_safe":   testValMarshaler{payload: []byte(`{"detector":"gitleaks"}`)},
		"ptr_marshaler_safe":   &testPtrMarshaler{payload: []byte(`{"detector":"semgrep"}`)},
		"ptr_marshaler_nil":    nilPtrMarshaler,
		"ptr_marshaler_struct": &ptrMarshalerStruct{PM: testPtrMarshaler{payload: []byte(`{"rule":"safe"}`)}},
		"ptr_marshaler_slice":  []testPtrMarshaler{{payload: []byte(`{"rule":"safe"}`)}},
		"non_addr_ptr_m_safe":  testPtrMarshaler{Safe: "ok", payload: []byte(`{"raw_secret":"not_called_by_json"}`)},
		"plain_bytes":          []byte(`{"raw_secret":"x"}`),
		"custom_bytes":         customBytes(`{"raw_secret":"x"}`),
		"time_val":             now,
		"time_ptr":             &now,
		"time_nil_ptr":         nilTimePtr,
	}
	if err := (Finding{Category: "SECRET", Redacted: true, Metadata: allowedMeta}).ValidateRedacted(); err != nil {
		t.Fatalf("safe raw/marshaler metadata returned unexpected err: %v", err)
	}
}

func TestModelAssessmentBlocksPublication(t *testing.T) {
	if (ModelAssessment{Status: AssessmentStatusComplete, Disposition: DispositionClear}).BlocksPublication() {
		t.Fatal("COMPLETE + CLEAR should not block publication")
	}
	if (ModelAssessment{Status: AssessmentStatusComplete, Disposition: DispositionReview}).BlocksPublication() {
		t.Fatal("COMPLETE + REVIEW should not block publication")
	}
	if (ModelAssessment{Status: AssessmentStatusComplete, Disposition: DispositionEscalate}).BlocksPublication() {
		t.Fatal("COMPLETE + ESCALATE should not block publication")
	}
	if !(ModelAssessment{Status: AssessmentStatusIndeterminate, Disposition: DispositionClear}).BlocksPublication() {
		t.Fatal("INDETERMINATE status must block publication")
	}
	if !(ModelAssessment{Status: AssessmentStatusComplete, Disposition: DispositionBlock}).BlocksPublication() {
		t.Fatal("BLOCK disposition must block publication")
	}
	if !(ModelAssessment{Status: AssessmentStatusComplete, Disposition: DispositionIndeterminate}).BlocksPublication() {
		t.Fatal("INDETERMINATE disposition must block publication")
	}
	if !(ModelAssessment{Status: AssessmentStatusComplete, Disposition: ""}).BlocksPublication() {
		t.Fatal("empty disposition on COMPLETE assessment must fail closed and block publication")
	}
	if !(ModelAssessment{Status: AssessmentStatusComplete, Disposition: Disposition("BOGUS")}).BlocksPublication() {
		t.Fatal("unknown disposition on COMPLETE assessment must fail closed and block publication")
	}
	if !Disposition("").BlocksPublication() || !Disposition("UNKNOWN").BlocksPublication() || !DispositionNotRequired.BlocksPublication() {
		t.Fatal("invalid or NOT_REQUIRED Disposition must fail closed in BlocksPublication")
	}
	notReq := ModelAssessment{Status: AssessmentStatusNotRequired, Disposition: DispositionNotRequired}
	if !notReq.BlocksPublication() {
		t.Fatal("NOT_REQUIRED ModelAssessment must fail closed in v1.0 BlocksPublication()")
	}
	if !notReq.AllowsPushEgress() {
		t.Fatal("NOT_REQUIRED ModelAssessment must permit PUSH_EGRESS via AllowsPushEgress()")
	}
	if notReq.BlocksStage(PolicyStagePushEgress) {
		t.Fatal("NOT_REQUIRED ModelAssessment must not block PolicyStagePushEgress")
	}
	if !notReq.BlocksStage(PolicyStageEgress) {
		t.Fatal("NOT_REQUIRED ModelAssessment must block PolicyStageEgress")
	}
	if (ModelAssessment{Status: AssessmentStatusNotRequired, Disposition: DispositionBlock}).AllowsPushEgress() {
		t.Fatal("NOT_REQUIRED + BLOCK must not allow push egress")
	}
	if (ModelAssessment{Status: AssessmentStatusNotRequired, Disposition: DispositionIndeterminate}).AllowsPushEgress() {
		t.Fatal("NOT_REQUIRED + INDETERMINATE must not allow push egress")
	}
	if !(ModelAssessment{Status: AssessmentStatusComplete, Disposition: DispositionClear}).AllowsPushEgress() {
		t.Fatal("COMPLETE + CLEAR must allow push egress")
	}
	if (ModelAssessment{Status: AssessmentStatusFailed, Disposition: DispositionClear}).AllowsPushEgress() {
		t.Fatal("FAILED assessment must not allow push egress")
	}
}

func TestApprovalIsActiveForManifest(t *testing.T) {
	digest := strings.Repeat("a", 64)
	other := strings.Repeat("b", 64)
	now := time.Now().UTC()

	a := Approval{
		Decision:       ApprovalDecisionApprove,
		ManifestDigest: digest,
	}
	if !a.IsActiveForManifest(digest) {
		t.Fatal("expected active approval for matching digest")
	}
	if !a.IsActiveForManifest("sha256:" + strings.ToUpper(digest)) {
		t.Fatal("expected case/prefix-normalized digest match")
	}
	if a.IsActiveForManifest(other) {
		t.Fatal("mismatched digest must not be active")
	}
	a.RevokedAt = &now
	if a.IsActiveForManifest(digest) {
		t.Fatal("revoked approval must not be active")
	}
	rej := Approval{Decision: ApprovalDecisionReject, ManifestDigest: digest}
	if rej.IsActiveForManifest(digest) {
		t.Fatal("REJECT must not be active")
	}
}

func TestValidateBranchRef(t *testing.T) {
	pid := MustNewID()
	if err := ValidateBranchRef(pid, "custodian/"+pid.String()); err != nil {
		t.Fatalf("expected valid short branch: %v", err)
	}
	if err := ValidateBranchRef(pid, "refs/heads/custodian/"+pid.String()); err != nil {
		t.Fatalf("expected valid full ref: %v", err)
	}
	bad := []string{
		"main",
		"refs/heads/main",
		"custodian/" + MustNewID().String(),
		"custodian/" + pid.String() + "/../main",
		"",
	}
	for _, b := range bad {
		if err := ValidateBranchRef(pid, b); !errors.Is(err, ErrForbidden) {
			t.Fatalf("ValidateBranchRef(%q) = %v, want ErrForbidden", b, err)
		}
	}
}

func TestSnapshotCapabilityValidate(t *testing.T) {
	now := time.Now().UTC()
	valid := SnapshotCapability{
		TokenID:     MustNewID(),
		WorkspaceID: MustNewID(),
		Generation:  1,
		ObjectKey:   "workspaces/ws/snapshots/snap.tar.gz",
		MaxBytes:    1024,
		UploadOnly:  true,
		IssuedTo:    MustNewID(),
		IssuedAt:    now,
		ExpiresAt:   now.Add(5 * time.Minute),
	}
	if err := valid.Validate(now); err != nil {
		t.Fatalf("expected valid capability, got %v", err)
	}

	notUploadOnly := valid
	notUploadOnly.UploadOnly = false
	if err := notUploadOnly.Validate(now); !errors.Is(err, ErrForbidden) {
		t.Fatalf("UploadOnly=false expected ErrForbidden, got %v", err)
	}

	expired := valid
	if err := expired.Validate(now.Add(5 * time.Minute)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expired expected ErrUnauthorized, got %v", err)
	}

	traversal := valid
	traversal.ObjectKey = "workspaces/../secret"
	if err := traversal.Validate(now); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("traversal object key expected ErrBadRequest, got %v", err)
	}

	nilIssuedTo := valid
	nilIssuedTo.IssuedTo = uuid.Nil
	if err := nilIssuedTo.Validate(now); !errors.Is(err, ErrForbidden) {
		t.Fatalf("nil IssuedTo expected ErrForbidden, got %v", err)
	}
}

func TestComputeAuditEventHash(t *testing.T) {
	actor := MustNewID()
	resID := MustNewID()
	ts := time.Date(2026, 11, 18, 22, 0, 0, 123456000, time.UTC)

	ev1 := AuditEvent{
		ID:           MustNewID(),
		EventType:    "WORKSPACE_CREATED",
		ActorID:      &actor,
		ResourceType: "workspace",
		ResourceID:   resID,
		Payload:      json.RawMessage(`{"b":2,"a":1}`),
		CreatedAt:    ts,
	}
	ev2 := ev1
	ev2.Payload = json.RawMessage(`{ "a": 1, "b": 2 }`)

	h1, err := ComputeAuditEventHash("", ev1)
	if err != nil {
		t.Fatalf("ComputeAuditEventHash(ev1): %v", err)
	}
	h2, err := ComputeAuditEventHash("", ev2)
	if err != nil {
		t.Fatalf("ComputeAuditEventHash(ev2): %v", err)
	}
	if h1 != h2 || !IsValidSHA256Hex(h1) {
		t.Fatalf("canonical payload hash mismatch or invalid: %s vs %s", h1, h2)
	}

	// Chained event detects tampering
	chained, err := ComputeAuditEventHash(h1, ev1)
	if err != nil {
		t.Fatalf("chained hash failed: %v", err)
	}
	if chained == h1 {
		t.Fatal("chained hash must differ when previousHash changes")
	}
	evTampered := ev1
	evTampered.EventType = "WORKSPACE_DELETED"
	hTampered, err := ComputeAuditEventHash("", evTampered)
	if err != nil {
		t.Fatalf("tampered hash failed: %v", err)
	}
	if hTampered == h1 {
		t.Fatal("tampered EventType did not alter hash")
	}
}

func TestPrincipalAndRepositoryHelpers(t *testing.T) {
	human := Principal{Kind: PrincipalKindHuman, DisplayName: "Alice Dev", VerifiedEmail: "alice@example.com"}
	name, email, err := human.GitAuthor()
	if err != nil || name != "Alice Dev" || email != "alice@example.com" {
		t.Fatalf("GitAuthor(human) unexpected: %q %q %v", name, email, err)
	}

	agent := Principal{Kind: PrincipalKindAgent, VerifiedEmail: "agent@example.com"}
	if _, _, err := agent.GitAuthor(); !errors.Is(err, ErrForbidden) {
		t.Fatalf("GitAuthor(agent) expected ErrForbidden, got %v", err)
	}

	repo := Repository{FullName: "acme/widget"}
	o, n, err := repo.OwnerRepo()
	if err != nil || o != "acme" || n != "widget" {
		t.Fatalf("OwnerRepo unexpected: %q %q %v", o, n, err)
	}
	if _, _, err := (Repository{FullName: "bad"}).OwnerRepo(); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("OwnerRepo(bad) expected ErrBadRequest, got %v", err)
	}
}

func TestPushApprovalReleaseIsUsableFor(t *testing.T) {
	now := time.Date(2026, 11, 23, 8, 0, 0, 0, time.UTC)
	principalID := MustNewID()
	reviewerID := MustNewID()
	digest := strings.Repeat("a", 64)

	valid := PushApprovalRelease{
		ID:                 MustNewID(),
		PrincipalID:        principalID,
		ApprovedBy:         reviewerID,
		Destination:        "github.com/acme/widget",
		DestinationHost:    "github.com",
		DestinationRepo:    "acme/widget",
		PushManifestDigest: digest,
		PushSessionID:      MustNewID(),
		PolicyDecisionID:   MustNewID(),
		ExpiresAt:          now.Add(15 * time.Minute),
		CreatedAt:          now.Add(-time.Minute),
	}
	if err := valid.IsUsableFor(now, principalID, "GitHub.com", "acme/widget", "sha256:"+strings.ToUpper(digest)); err != nil {
		t.Fatalf("expected valid approval release, got %v", err)
	}

	// Also works when only canonical Destination ("host/owner/repo") is populated (e.g. from DB row).
	dbLoaded := valid
	dbLoaded.DestinationHost = ""
	dbLoaded.DestinationRepo = ""
	if err := dbLoaded.IsUsableFor(now, principalID, "github.com", "acme/widget", digest); err != nil {
		t.Fatalf("expected DB-loaded destination match, got %v", err)
	}

	revoked := valid
	revokedAt := now.Add(-10 * time.Second)
	revoked.RevokedAt = &revokedAt
	if err := revoked.IsUsableFor(now, principalID, "github.com", "acme/widget", digest); !errors.Is(err, ErrForbidden) {
		t.Fatalf("revoked expected ErrForbidden, got %v", err)
	}

	consumed := valid
	consumed.ConsumedAt = &revokedAt
	if err := consumed.IsUsableFor(now, principalID, "github.com", "acme/widget", digest); !errors.Is(err, ErrForbidden) {
		t.Fatalf("consumed expected ErrForbidden, got %v", err)
	}

	expired := valid
	if err := expired.IsUsableFor(valid.ExpiresAt, principalID, "github.com", "acme/widget", digest); !errors.Is(err, ErrForbidden) {
		t.Fatalf("expired expected ErrForbidden, got %v", err)
	}

	wrongPrincipal := valid
	if err := wrongPrincipal.IsUsableFor(now, MustNewID(), "github.com", "acme/widget", digest); !errors.Is(err, ErrForbidden) {
		t.Fatalf("wrong principal expected ErrForbidden, got %v", err)
	}

	selfApproved := valid
	selfApproved.ApprovedBy = principalID
	if err := selfApproved.IsUsableFor(now, principalID, "github.com", "acme/widget", digest); !errors.Is(err, ErrForbidden) {
		t.Fatalf("self-approval expected ErrForbidden, got %v", err)
	}

	if err := valid.IsUsableFor(now, principalID, "evil.com", "acme/widget", digest); !errors.Is(err, ErrForbidden) {
		t.Fatalf("wrong host expected ErrForbidden, got %v", err)
	}
	if err := valid.IsUsableFor(now, principalID, "github.com", "acme/other", digest); !errors.Is(err, ErrForbidden) {
		t.Fatalf("wrong repo expected ErrForbidden, got %v", err)
	}
	if err := dbLoaded.IsUsableFor(now, principalID, "evil.com", "github.com/acme/widget", digest); !errors.Is(err, ErrForbidden) {
		t.Fatalf("host/repo confusion expected ErrForbidden, got %v", err)
	}
	if err := valid.IsUsableFor(now, principalID, "github.com", "acme/widget", strings.Repeat("b", 64)); !errors.Is(err, ErrForbidden) {
		t.Fatalf("digest mismatch expected ErrForbidden, got %v", err)
	}
}

func TestIPFingerprintCorpusAndMetadataValidation(t *testing.T) {
	if err := (IPFingerprintCorpus{Classification: ClassificationRestricted}).ValidateClassification(); err != nil {
		t.Fatalf("RESTRICTED should be allowed: %v", err)
	}
	if err := (IPFingerprintCorpus{Classification: ClassificationConfidential}).ValidateClassification(); err != nil {
		t.Fatalf("CONFIDENTIAL should be allowed: %v", err)
	}
	for _, cls := range []Classification{ClassificationPublic, ClassificationInternal, Classification("")} {
		if err := (IPFingerprintCorpus{Classification: cls}).ValidateClassification(); !errors.Is(err, ErrUnprocessable) {
			t.Fatalf("classification %q expected ErrUnprocessable, got %v", cls, err)
		}
	}

	safeMeta := map[string]any{
		"language":         "go",
		"chunk_bytes":      4096,
		"token_count":      42,
		"source_ref":       "refs/heads/main",
		"content_type":     "text/plain",
		"redacted_preview": "sha256:abcd",
		"raw_safe":         true,
		"winnow_k":         25,
		"nested":           map[string]string{"algorithm": "winnowing"},
	}
	if err := ValidateIPFingerprintMetadata(safeMeta); err != nil {
		t.Fatalf("safe metadata unexpected err: %v", err)
	}

	forbiddenIPKeys := []string{
		"raw_source", "RawSource", "rawSource", "raw-source", "raw source", "raw.source",
		"raw_code", "RawCode", "rawCode", "raw-code",
		"source_text", "SourceText", "sourceText", "source-text",
		"content", "Content",
		"snippet", "Snippet",
		"raw_secret", "RawSecret", "rawSecret", "raw-secret",
		"match_raw", "MatchRaw", "matchRaw",
		"private_key", "PrivateKey", "privateKey",
		"token", "Token",
		"password", "Password",
		"credential", "Credential",
	}
	for _, key := range forbiddenIPKeys {
		meta := map[string]any{"nested": map[string]any{key: "secret-code"}}
		if err := ValidateIPFingerprintMetadata(meta); !errors.Is(err, ErrUnprocessable) {
			t.Fatalf("forbidden key %q expected ErrUnprocessable, got %v", key, err)
		}
	}

	type untaggedIPMeta struct {
		RawSource string
	}
	if err := ValidateIPFingerprintMetadata(map[string]any{
		"struct": untaggedIPMeta{RawSource: "secret()"},
	}); !errors.Is(err, ErrUnprocessable) {
		t.Fatalf("untagged struct RawSource expected ErrUnprocessable, got %v", err)
	}
	if err := ValidateIPFingerprintMetadata(map[string]any{
		"raw": json.RawMessage(`{"rawSource":"secret()"}`),
	}); !errors.Is(err, ErrUnprocessable) {
		t.Fatalf("json.RawMessage rawSource expected ErrUnprocessable, got %v", err)
	}

	type untaggedFindingMeta struct {
		RawSecret string
	}
	for name, meta := range map[string]map[string]any{
		"untagged_struct_RawSecret": {"s": untaggedFindingMeta{RawSecret: "ghp_123"}},
		"camelCase_privateKey":      {"privateKey": "pem"},
		"kebabCase_raw_secret":      {"raw-secret": "x"},
		"raw_message_matchRaw":      {"payload": json.RawMessage(`{"matchRaw":"x"}`)},
	} {
		f := Finding{Category: "SECRET", Redacted: true, Metadata: meta}
		if err := f.ValidateRedacted(); !errors.Is(err, ErrUnprocessable) {
			t.Fatalf("%s expected ErrUnprocessable, got %v", name, err)
		}
	}

	allowedFinding := Finding{
		Category: "SECRET",
		Redacted: true,
		Metadata: map[string]any{
			"token_count":      1,
			"secret_detected":  true,
			"redacted_preview": "AKIA***",
			"source_ref":       "a.go",
		},
	}
	if err := allowedFinding.ValidateRedacted(); err != nil {
		t.Fatalf("legitimate finding metadata unexpected err: %v", err)
	}
}
