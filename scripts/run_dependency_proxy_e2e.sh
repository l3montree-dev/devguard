#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROXY_BASE_URL="${PROXY_BASE_URL:-http://localhost:8080/api/v1/dependency-proxy}"

if ! command -v go >/dev/null 2>&1; then
  echo "go is required"
  exit 1
fi
if ! command -v npm >/dev/null 2>&1; then
  echo "npm is required"
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required"
  exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required"
  exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required"
  exit 1
fi

echo "Checking dependency proxy availability at ${PROXY_BASE_URL}"
if ! curl --max-time 3 --silent --show-error "${PROXY_BASE_URL}" >/dev/null; then
  echo "Dependency proxy is not reachable at ${PROXY_BASE_URL}. Start devguard first (e.g. make run)."
  exit 1
fi

WORK_DIR="$(mktemp -d /tmp/devguard-proxy-e2e-XXXXXX)"

cleanup() {
  chmod -R u+w "${WORK_DIR}" 2>/dev/null || true
  rm -rf "${WORK_DIR}" 2>/dev/null || true
}
trap cleanup EXIT

run_expect_failure() {
  local name="$1"
  local logfile="$2"
  shift 2

  echo "Running ${name} (expected to fail due to blocked malicious package)"
  if "$@" >"${logfile}" 2>&1; then
    echo "${name}: expected failure, but command succeeded"
    echo "--- ${name} output ---"
    cat "${logfile}"
    echo "----------------------"
    return 1
  fi

  if grep -Eiq "blocked|forbidden|malicious|not allowed" "${logfile}"; then
    echo "${name}: failed as expected and reported a block"
  else
    echo "${name}: failed as expected"
  fi
}

run_expect_success() {
  local name="$1"
  local logfile="$2"
  shift 2

  echo "Running ${name} (expected to succeed for allowed package)"
  if ! "$@" >"${logfile}" 2>&1; then
    echo "${name}: expected success, but command failed"
    echo "--- ${name} output ---"
    cat "${logfile}"
    echo "----------------------"
    return 1
  fi

  echo "${name}: succeeded as expected"
}

run_go_test() {
  local positive_dir="${WORK_DIR}/test-go-positive"
  local test_dir="${WORK_DIR}/test-go-project"
  mkdir -p "${positive_dir}"
  cp -R "${ROOT_DIR}/tests/test-go-project" "${test_dir}"

  pushd "${positive_dir}" >/dev/null
  go mod init devguard/proxy-positive-go >/dev/null 2>&1
  run_expect_success \
    "go-proxy-positive" \
    "${WORK_DIR}/go-positive.log" \
    env \
      GOPATH="${WORK_DIR}/gopath" \
      GOMODCACHE="${WORK_DIR}/pkg/mod" \
      GOPROXY="${PROXY_BASE_URL}/go" \
      go get github.com/sirupsen/logrus@v1.9.3
  popd >/dev/null

  pushd "${test_dir}" >/dev/null
  run_expect_failure \
    "go-proxy-fixture" \
    "${WORK_DIR}/go.log" \
    env \
      GOPATH="${WORK_DIR}/gopath" \
      GOMODCACHE="${WORK_DIR}/pkg/mod" \
      GOPROXY="${PROXY_BASE_URL}/go" \
      go get github.com/fake-org/malicious-package
  popd >/dev/null
}

run_npm_test() {
  local test_dir="${WORK_DIR}/test-npm-project"
  cp -R "${ROOT_DIR}/tests/test-npm-project" "${test_dir}"

  pushd "${test_dir}" >/dev/null
  run_expect_failure \
    "npm-proxy-fixture" \
    "${WORK_DIR}/npm.log" \
    npm install --ignore-scripts --no-audit --fund=false
  popd >/dev/null
}

run_pypi_test() {
  local test_dir="${WORK_DIR}/test-pypi-project"
  mkdir -p "${test_dir}"
  cp "${ROOT_DIR}/tests/test-pypi-project/requirements.txt" "${test_dir}/requirements.txt"

  pushd "${test_dir}" >/dev/null
  python3 -m venv venv
  # shellcheck disable=SC1091
  source venv/bin/activate

  run_expect_success \
    "pypi-proxy-positive" \
    "${WORK_DIR}/pypi-positive.log" \
    env \
      PIP_INDEX_URL="${PROXY_BASE_URL}/pypi/simple" \
      PIP_TRUSTED_HOST="localhost" \
      python3 -m pip install requests==2.32.3

  run_expect_failure \
    "pypi-proxy-fixture" \
    "${WORK_DIR}/pypi.log" \
    env \
      PIP_INDEX_URL="${PROXY_BASE_URL}/pypi/simple" \
      PIP_TRUSTED_HOST="localhost" \
      python3 -m pip install -r requirements.txt

  deactivate
  popd >/dev/null
}

run_oci_test() {
  # The OCI registry sits at /v2/ on the same host as the API.
  # Strip scheme and /api/v1/dependency-proxy suffix to get bare host:port.
  local api_host
  api_host="$(echo "${PROXY_BASE_URL}" | sed 's|https\?://||; s|/api/v1/dependency-proxy||')"

  # On macOS, Docker Desktop's daemon runs inside a Linux VM and cannot reach
  # the host via 'localhost'. Use host.docker.internal instead.
  local proxy_host="${api_host}"
  if [[ "$(uname)" == "Darwin" ]]; then
    proxy_host="$(echo "${api_host}" | sed 's|localhost|host.docker.internal|; s|127\.0\.0\.1|host.docker.internal|')"
  fi

  # Docker pull format: <host>/<registry>/<namespace>/<image>:<tag>
  # Docker connects to <host>, sends GET /v2/<registry>/<namespace>/<image>/manifests/<tag>

  # Positive — pull a well-known public image through the proxy.
  run_expect_success \
    "oci-pull-positive" \
    "${WORK_DIR}/oci-positive.log" \
    docker pull --quiet "${proxy_host}/docker.io/library/alpine:latest"

  docker rmi "${proxy_host}/docker.io/library/alpine:latest" >/dev/null 2>&1 || true

  # Negative — the fake malicious OCI image must be blocked.
  run_expect_failure \
    "oci-pull-negative" \
    "${WORK_DIR}/oci-negative.log" \
    docker pull "${proxy_host}/docker.io/fake-org/malicious-image:latest"
}

run_go_test
run_npm_test
run_pypi_test
run_oci_test

echo "Dependency proxy e2e checks passed"
