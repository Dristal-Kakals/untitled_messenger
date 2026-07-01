#!/usr/bin/env bash
# Production build script for the untitled_messenger workspace.
#
# Runs the full release pipeline: format check, clippy (warnings as errors),
# release build of every workspace member, and the test suite in release mode.
# Exits non-zero on any failure so it is safe to wire into CI.
#
# Usage:
#   ./build.sh              # full pipeline (fmt + clippy + build + test)
#   ./build.sh --no-test    # skip the test step
#   ./build.sh --no-fmt     # skip cargo fmt --check
#   ./build.sh --clean      # cargo clean before building
#   ./build.sh --help

set -euo pipefail

# Resolve the workspace root from the script location so it works from any cwd.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RUN_FMT=1
RUN_TEST=1
RUN_CLEAN=0

for arg in "$@"; do
  case "$arg" in
    --no-fmt)  RUN_FMT=0 ;;
    --no-test) RUN_TEST=0 ;;
    --clean)   RUN_CLEAN=1 ;;
    --help|-h)
      sed -n '2,12p' "$0"
      exit 0
      ;;
    *)
      echo "build.sh: unknown option '$arg' (try --help)" >&2
      exit 2
      ;;
  esac
done

# Colorized step headers only when stdout is a tty; otherwise plain text for logs.
if [[ -t 1 ]]; then
  step() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
  fail() { printf '\033[1;31m!! %s\033[0m\n' "$*" >&2; }
else
  step() { printf '\n==> %s\n' "$*"; }
  fail() { printf '!! %s\n' "$*" >&2; }
fi

trap 'fail "build failed at step: ${CURRENT_STEP:-unknown}"' ERR

if [[ "$RUN_CLEAN" -eq 1 ]]; then
  CURRENT_STEP="cargo clean"
  step "cleaning target/"
  cargo clean
fi

CURRENT_STEP="cargo fmt --check"
if [[ "$RUN_FMT" -eq 1 ]]; then
  step "checking formatting"
  cargo fmt --all -- --check
fi

CURRENT_STEP="cargo clippy"
step "clippy (warnings as errors)"
cargo clippy --all-targets --all-features -- -D warnings

CURRENT_STEP="cargo build --release"
step "release build (all workspace members)"
cargo build --release --all-targets --workspace

CURRENT_STEP="cargo test --release"
if [[ "$RUN_TEST" -eq 1 ]]; then
  step "release tests (all workspace members)"
  cargo test --release --all-targets --workspace
fi

CURRENT_STEP="done"
step "build complete"
echo "artifacts under: target/release"
