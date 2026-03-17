#!/usr/bin/env bash
set -euo pipefail

DOCKER_CMD="${DOCKER:-docker}"
IMAGE_PLATFORM="${IMAGE_PLATFORM:-linux/amd64,linux/arm64}"
TARGETS="${TARGETS:-cpv-e2eviv de-ple-e2eviv isabelle-e2eviv}"
PRUNE="${PRUNE:-no}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

usage() {
    cat <<'EOF'
Estimate Docker storage usage empirically by building one or more repository images.

Environment variables:
  DOCKER=<docker|podman>          container engine to use (default: docker)
  IMAGE_PLATFORM=<platform list>  build platform(s) to pass through
  TARGETS="dir1 dir2 ..."         image directories under docker/ to measure
  PRUNE=<yes|no>                  whether to prune Docker data before measuring

Examples:
  make -C docker estimate-space TARGETS="cpv-e2eviv" IMAGE_PLATFORM=linux/amd64 PRUNE=yes
  make -C docker estimate-space TARGETS="cpv-e2eviv isabelle-e2eviv"
EOF
}

is_yes() {
    case "$1" in
        [Yy][Ee][Ss]|[Tt][Rr][Uu][Ee]|1) return 0 ;;
        *) return 1 ;;
    esac
}

print_storage_summary() {
    echo "[info] docker system df"
    "${DOCKER_CMD}" system df || true
    echo
    if "${DOCKER_CMD}" builder du >/dev/null 2>&1; then
        echo "[info] docker builder du"
        "${DOCKER_CMD}" builder du || true
    else
        echo "[warn] '${DOCKER_CMD} builder du' is not supported by this runtime"
    fi
}

print_image_size() {
    local image="$1"
    local size_bytes

    size_bytes=$("${DOCKER_CMD}" image inspect "${image}" --format '{{.Size}}' 2>/dev/null || true)
    if [[ -n "${size_bytes}" ]]; then
        echo "[info] final local image size for ${image}: ${size_bytes} bytes"
    else
        echo "[info] no local image named ${image} is currently present"
    fi
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi

echo "=== Docker storage estimate ==="
echo "[info] engine: ${DOCKER_CMD}"
echo "[info] targets: ${TARGETS}"
echo "[info] image platform(s): ${IMAGE_PLATFORM}"
echo "[info] tip: for the cleanest per-image estimate, set PRUNE=yes and TARGETS to a single image directory"
echo

if is_yes "${PRUNE}"; then
    echo "=== Pruning existing Docker data ==="
    "${DOCKER_CMD}" system prune -af --volumes || true
    "${DOCKER_CMD}" builder prune -af || true
    echo
fi

echo "=== Baseline storage summary ==="
print_storage_summary

for dir in ${TARGETS}; do
    echo
    echo "=== Building ${dir} ==="
    if [[ ! -d "${DOCKER_DIR}/${dir}" ]]; then
        echo "[error] unknown image directory: ${dir}" >&2
        exit 2
    fi

    set +e
    make -C "${DOCKER_DIR}/${dir}" image DOCKER="${DOCKER_CMD}" IMAGE_PLATFORM="${IMAGE_PLATFORM}"
    status=$?
    set -e

    if [[ ${status} -eq 0 ]]; then
        echo "[info] build completed for ${dir}"
    else
        echo "[warn] build failed for ${dir} with exit code ${status}"
    fi

    print_image_size "${dir}"
    echo "[info] storage summary after ${dir}:"
    print_storage_summary
done
