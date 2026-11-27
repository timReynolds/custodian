#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: test/e2e/run_e2e.sh [OPTIONS]

Opaque-box E2E test runner for Custodian.

Options:
  --tier=1|2|3|4|all   Select E2E tier to execute (default: all; includes TestT*_PG_* tests)
  --push-gateway       Run only Push Gateway E2E tests (^TestT[1-4]_PG_* / ^TestT<N>_PG_*)
  --harness-only       Run only the harness self-tests (./test/e2e/harness/...)
  --compile-only       Run go vet, import isolation check, and go test -c without executing tests
  -v, --verbose        Pass -v to go test (enabled by default)
  -h, --help           Show this help message and exit
EOF
}

TIER="all"
PUSH_GATEWAY=0
HARNESS_ONLY=0
COMPILE_ONLY=0
VERBOSE=1

while [ $# -gt 0 ]; do
  case "$1" in
    --tier=*)
      TIER="${1#*=}"
      shift
      ;;
    --tier)
      if [ $# -lt 2 ]; then
        echo "error: --tier requires an argument" >&2
        exit 2
      fi
      TIER="$2"
      shift 2
      ;;
    --harness-only)
      HARNESS_ONLY=1
      shift
      ;;
    --push-gateway)
      PUSH_GATEWAY=1
      shift
      ;;
    --compile-only)
      COMPILE_ONLY=1
      shift
      ;;
    -v|--verbose)
      VERBOSE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "$TIER" in
  1|2|3|4|all) ;;
  *)
    echo "error: invalid --tier value '$TIER' (expected 1|2|3|4|all)" >&2
    exit 2
    ;;
esac

# Resolve Go toolchain: CUSTODIAN_GO_BIN -> PATH -> fallback toolchain
GO_BIN=""
if [ -n "${CUSTODIAN_GO_BIN:-}" ]; then
  if [ -x "$CUSTODIAN_GO_BIN" ]; then
    GO_BIN="$CUSTODIAN_GO_BIN"
  else
    echo "error: CUSTODIAN_GO_BIN='$CUSTODIAN_GO_BIN' is not executable" >&2
    exit 1
  fi
elif command -v go >/dev/null 2>&1; then
  GO_BIN="$(command -v go)"
elif [ -x "/Users/tim/Code/github.com/timreynolds/forge/data/kind/tools/go/bin/go" ]; then
  GO_BIN="/Users/tim/Code/github.com/timreynolds/forge/data/kind/tools/go/bin/go"
else
  echo "error: unable to find go binary (set CUSTODIAN_GO_BIN or install go on PATH)" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Clean Git & E2E environment
export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_TERMINAL_PROMPT=0
export CUSTODIAN_E2E_ROOT="$REPO_ROOT"

cd "$REPO_ROOT"

# Pre-flight check 1: no nested test/e2e/go.mod
if [ -e "$REPO_ROOT/test/e2e/go.mod" ]; then
  echo "error: forbidden nested module file found at test/e2e/go.mod; test/e2e must share root go.mod" >&2
  exit 1
fi

# Pre-flight check 2: root go.mod must exist
if [ ! -f "$REPO_ROOT/go.mod" ]; then
  echo "error: $REPO_ROOT/go.mod not found. Follow the temporary probe-dir procedure in test/e2e/README.md for pre-go.mod verification." >&2
  exit 1
fi

# Pre-flight check 3: verify zero internal/* imports in test/e2e/... and stdlib-only in test/e2e/harness/...
IMPORT_LIST="$("$GO_BIN" list -f '{{.ImportPath}} -> {{.Imports}} {{.TestImports}} {{.XTestImports}}' ./test/e2e/...)"
if printf '%s\n' "$IMPORT_LIST" | grep -q 'github.com/timreynolds/custodian/internal/'; then
  echo "error: opaque-box violation: test/e2e imports internal/* packages:" >&2
  printf '%s\n' "$IMPORT_LIST" | grep 'github.com/timreynolds/custodian/internal/' >&2
  exit 1
fi

HARNESS_IMPORTS="$("$GO_BIN" list -f '{{range .Imports}}{{.}}{{"\n"}}{{end}}{{range .TestImports}}{{.}}{{"\n"}}{{end}}{{range .XTestImports}}{{.}}{{"\n"}}{{end}}' ./test/e2e/harness/...)"
NON_STDLIB="$(printf '%s\n' "$HARNESS_IMPORTS" | grep '\.' | grep -v '^github.com/timreynolds/custodian/test/e2e/harness$' || true)"
if [ -n "$NON_STDLIB" ]; then
  echo "error: test/e2e/harness must use Go stdlib only; found non-stdlib imports:" >&2
  printf '%s\n' "$NON_STDLIB" >&2
  exit 1
fi

PKG="./test/e2e/..."
RUN_ARGS=()

if [ "$HARNESS_ONLY" -eq 1 ]; then
  if [ "$PUSH_GATEWAY" -eq 1 ]; then
    echo "error: --harness-only and --push-gateway cannot be combined" >&2
    exit 2
  fi
  PKG="./test/e2e/harness/..."
elif [ "$PUSH_GATEWAY" -eq 1 ]; then
  PKG="./test/e2e"
  case "$TIER" in
    1)
      RUN_ARGS=(-run '^TestT1_PG_')
      ;;
    2)
      RUN_ARGS=(-run '^TestT2_PG_')
      ;;
    3)
      RUN_ARGS=(-run '^TestT3_PG_')
      ;;
    4)
      RUN_ARGS=(-run '^TestT4_PG_')
      ;;
    all)
      RUN_ARGS=(-run '^TestT[1-4]_PG_')
      ;;
  esac
else
  case "$TIER" in
    1)
      PKG="./test/e2e"
      RUN_ARGS=(-run '^TestT1_')
      ;;
    2)
      PKG="./test/e2e"
      RUN_ARGS=(-run '^TestT2_')
      ;;
    3)
      PKG="./test/e2e"
      RUN_ARGS=(-run '^TestT3_')
      ;;
    4)
      PKG="./test/e2e"
      RUN_ARGS=(-run '^TestT4_')
      ;;
    all)
      PKG="./test/e2e/..."
      ;;
  esac
fi

if [ "$COMPILE_ONLY" -eq 1 ]; then
  TMP_BIN_DIR="$(mktemp -d)"
  trap 'rm -rf "$TMP_BIN_DIR"' EXIT
  "$GO_BIN" vet "$PKG"
  idx=0
  for p in $("$GO_BIN" list "$PKG"); do
    idx=$((idx + 1))
    "$GO_BIN" test -c -o "$TMP_BIN_DIR/e2e_${idx}.test" "$p"
  done
  echo "Compile-only verification succeeded for $PKG"
  exit 0
fi

PREBUILT_BIN_DIR=""
cleanup_prebuilt_bins() {
  if [ -n "$PREBUILT_BIN_DIR" ] && [ -d "$PREBUILT_BIN_DIR" ]; then
    rm -rf "$PREBUILT_BIN_DIR"
  fi
}

if [ "$HARNESS_ONLY" -eq 0 ] && [ -z "${CUSTODIAN_E2E_BIN_DIR:-}" ]; then
  PREBUILT_BIN_DIR="$(mktemp -d)"
  trap cleanup_prebuilt_bins EXIT
  for bin in custodian custodian-api custodian-worker custodian-publisher custodian-policy; do
    "$GO_BIN" build -o "$PREBUILT_BIN_DIR/$bin" "./cmd/$bin"
  done
  if [ -d "./cmd/custodian-git-gateway" ] && ls ./cmd/custodian-git-gateway/*.go >/dev/null 2>&1; then
    "$GO_BIN" build -o "$PREBUILT_BIN_DIR/custodian-git-gateway" "./cmd/custodian-git-gateway"
  fi
  export CUSTODIAN_E2E_BIN_DIR="$PREBUILT_BIN_DIR"
fi

DEFAULT_TIMEOUT="30m"
if [ "$TIER" = "all" ] && [ "$PUSH_GATEWAY" -eq 0 ] && [ "$HARNESS_ONLY" -eq 0 ]; then
  DEFAULT_TIMEOUT="60m"
fi
TEST_TIMEOUT="${CUSTODIAN_E2E_TIMEOUT:-$DEFAULT_TIMEOUT}"
TEST_FLAGS=(-count=1 -timeout="$TEST_TIMEOUT")
if [ "$VERBOSE" -eq 1 ]; then
  TEST_FLAGS+=(-v)
fi

"$GO_BIN" test "${TEST_FLAGS[@]}" "${RUN_ARGS[@]}" "$PKG"
