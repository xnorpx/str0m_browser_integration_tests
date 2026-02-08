#!/usr/bin/env bash
# Run all Rust + browser integration tests.
# Usage: ./run-all-tests.sh
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

PASS=0
FAIL=0
SKIPPED=0
FAILURES=()

run() {
  local label="$1"; shift
  echo -e "\n${CYAN}${BOLD}> ${label}${NC}"
  if "$@"; then
    echo -e "${GREEN}[PASS] ${label}${NC}"
    ((PASS++))
  else
    echo -e "${RED}[FAIL] ${label}${NC}"
    FAILURES+=("$label")
    ((FAIL++))
  fi
}

# -- Rust tests -------------------------------------------------------
echo -e "${BOLD}===============================================${NC}"
echo -e "${BOLD}  Rust tests${NC}"
echo -e "${BOLD}===============================================${NC}"

run "cargo build (release)"  cargo build --release --bin server
run "cargo test"             cargo test --release

# -- Install web dependencies -----------------------------------------
echo -e "\n${BOLD}===============================================${NC}"
echo -e "${BOLD}  Installing npm dependencies${NC}"
echo -e "${BOLD}===============================================${NC}"
(cd web && npm ci)

export PREBUILT_SERVER_BINARY="$(pwd)/target/release/server"

# -- Detect installed browsers ----------------------------------------
has_chrome=false
has_edge=false
has_firefox=false

# Chrome
if command -v google-chrome &>/dev/null || command -v google-chrome-stable &>/dev/null || \
   [ -x "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" ]; then
  has_chrome=true
fi

# Edge
if command -v microsoft-edge &>/dev/null || command -v microsoft-edge-stable &>/dev/null || \
   [ -x "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge" ]; then
  has_edge=true
fi

# Firefox
if command -v firefox &>/dev/null || \
   [ -x "/Applications/Firefox.app/Contents/MacOS/firefox" ]; then
  has_firefox=true
fi

echo -e "\n${BOLD}Detected browsers:${NC}"
echo "  Chrome:  $has_chrome"
echo "  Edge:    $has_edge"
echo "  Firefox: $has_firefox"

# -- Base browser tests -----------------------------------------------
echo -e "\n${BOLD}===============================================${NC}"
echo -e "${BOLD}  Base browser tests${NC}"
echo -e "${BOLD}===============================================${NC}"

if $has_chrome; then
  run "Base · Chrome"  npm run test:chrome
else
  echo -e "${CYAN}[SKIP] Skipping Chrome (not found)${NC}"; ((SKIPPED++))
fi

if $has_edge; then
  run "Base · Edge"    npm run test:edge
else
  echo -e "${CYAN}[SKIP] Skipping Edge (not found)${NC}"; ((SKIPPED++))
fi

if $has_firefox; then
  run "Base · Firefox" npm run test:firefox
else
  echo -e "${CYAN}[SKIP] Skipping Firefox (not found)${NC}"; ((SKIPPED++))
fi

# -- Feature tests (SNAP / SPED / WARP) ------------------------------
echo -e "\n${BOLD}===============================================${NC}"
echo -e "${BOLD}  Feature tests (SNAP / SPED / WARP)${NC}"
echo -e "${BOLD}===============================================${NC}"

if $has_chrome; then
  run "SNAP · Chrome"  npm run test:snap:chrome
  run "SPED · Chrome"  npm run test:sped:chrome
  run "WARP · Chrome"  npm run test:warp:chrome
else
  echo -e "${CYAN}[SKIP] Skipping SNAP/SPED/WARP Chrome (not found)${NC}"; ((SKIPPED+=3))
fi

if $has_edge; then
  run "SPED · Edge"    npm run test:sped:edge
else
  echo -e "${CYAN}[SKIP] Skipping SPED Edge (not found)${NC}"; ((SKIPPED++))
fi

# -- Summary ----------------------------------------------------------
echo -e "\n${BOLD}===============================================${NC}"
echo -e "${BOLD}  Summary${NC}"
echo -e "${BOLD}===============================================${NC}"
echo -e "  ${GREEN}Passed:  ${PASS}${NC}"
echo -e "  ${RED}Failed:  ${FAIL}${NC}"
echo -e "  ${CYAN}Skipped: ${SKIPPED}${NC}"

if [ ${FAIL} -gt 0 ]; then
  echo -e "\n${RED}${BOLD}Failed tests:${NC}"
  for f in "${FAILURES[@]}"; do
    echo -e "  ${RED}[FAIL] ${f}${NC}"
  done
  exit 1
fi

echo -e "\n${GREEN}${BOLD}All tests passed!${NC}"
