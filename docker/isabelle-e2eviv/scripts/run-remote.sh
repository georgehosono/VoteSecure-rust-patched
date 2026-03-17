#!/bin/bash
set -euo pipefail

# Docker-compatible runtime command to use.
DOCKER_CMD="${DOCKER:-docker}"

# URL of the Docker repository (Docker Hub)
REPOSITORY="registry-1.docker.io"

# Name of the image provider
PROVIDER="freeandfair"

# Name of the docker image to run
IMAGE="isabelle-e2eviv"

# Fully qualified image reference
IMAGE_REF="$PROVIDER/$IMAGE:latest"

# Working directory inside container
WORKDIR="/work"

# Volume mapping. We map the current directory.
VOLUME="$PWD:$WORKDIR"

# Optional authenticated login (for rate limits/private mirrors).
if [[ -n "${DOCKER_READ_ONLY_TOKEN:-}" && -n "${DOCKER_READ_ONLY_TOKEN_USERNAME:-}" ]]; then
  echo "Logging in to $REPOSITORY with read-only token credentials."
  printf '%s\n' "$DOCKER_READ_ONLY_TOKEN" \
    | "$DOCKER_CMD" login "$REPOSITORY" -u "$DOCKER_READ_ONLY_TOKEN_USERNAME" --password-stdin
else
  echo "No Docker read-only token provided; continuing with anonymous pull."
fi

# Ensure the remote image is present.
"$DOCKER_CMD" pull "$IMAGE_REF"

# Print an informative message about volume mapping.
echo "Mapping current folder to $WORKDIR inside the container."

# Run container interactively and automatically destroy it when exiting.
"$DOCKER_CMD" run -it --rm -v "$VOLUME" -w "$WORKDIR" "$IMAGE_REF"
