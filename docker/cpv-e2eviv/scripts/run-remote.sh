#!/bin/bash
set -euo pipefail

DOCKER_CMD="${DOCKER:-docker}"
REPOSITORY="registry-1.docker.io"
ORGANIZATION="freeandfair"
IMAGE="cpv-e2eviv"
IMAGE_REF="$ORGANIZATION/$IMAGE:latest"
WORKDIR="/work"
VOLUME="$PWD:$WORKDIR"

# Optional authenticated login (for rate limits/private mirrors).
if [[ -n "${DOCKER_READ_ONLY_TOKEN:-}" && -n "${DOCKER_READ_ONLY_TOKEN_USERNAME:-}" ]]; then
  echo "Logging in to $REPOSITORY with read-only token credentials."
  printf '%s\n' "$DOCKER_READ_ONLY_TOKEN" \
    | "$DOCKER_CMD" login "$REPOSITORY" -u "$DOCKER_READ_ONLY_TOKEN_USERNAME" --password-stdin
else
  echo "No Docker read-only token provided; continuing with anonymous pull."
fi

"$DOCKER_CMD" pull "$IMAGE_REF"

echo "Mapping current folder to $WORKDIR inside the container."
"$DOCKER_CMD" run -it --rm -v "$VOLUME" -w "$WORKDIR" "$IMAGE_REF"
