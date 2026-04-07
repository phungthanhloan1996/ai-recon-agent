#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-all-plus-tool-cache}"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS_DIR="${PROJECT_ROOT}/results"

cleanup_results_all() {
  if [[ -d "${RESULTS_DIR}" ]]; then
    find "${RESULTS_DIR}" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
  fi
}

cleanup_results_run() {
  local run_dir="${2:-}"
  if [[ -z "${run_dir}" ]]; then
    echo "Usage: $0 run <results-subdir-or-absolute-path>" >&2
    exit 1
  fi

  if [[ "${run_dir}" != /* ]]; then
    run_dir="${RESULTS_DIR}/${run_dir}"
  fi

  rm -rf "${run_dir}"
}

cleanup_tool_cache() {
  rm -rf \
    "${HOME}/.local/share/sqlmap/output" \
    "${HOME}/.sqlmap/output" \
    /tmp/sqlmap/output
}

cleanup_project_cache() {
  if [[ -d "${RESULTS_DIR}" ]]; then
    find "${RESULTS_DIR}" -type d -name _cache -exec rm -rf {} +
  fi
}

case "${MODE}" in
  all)
    cleanup_results_all
    ;;
  run)
    cleanup_results_run "$@"
    ;;
  tool-cache)
    cleanup_tool_cache
    ;;
  project-cache)
    cleanup_project_cache
    ;;
  all-plus-tool-cache)
    cleanup_results_all
    cleanup_project_cache
    cleanup_tool_cache
    ;;
  *)
    cat >&2 <<'EOF'
Usage:
  scripts/clean_results.sh all
  scripts/clean_results.sh run <results-subdir-or-absolute-path>
  scripts/clean_results.sh project-cache
  scripts/clean_results.sh tool-cache
  scripts/clean_results.sh all-plus-tool-cache
EOF
    exit 1
    ;;
esac

echo "Cleanup complete: ${MODE}"
