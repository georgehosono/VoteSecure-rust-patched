#!/bin/bash
set -euo pipefail

# Docker-compatible runtime command to use.
DOCKER_CMD="${DOCKER:-docker}"

# Name of the docker image to run
IMAGE="isabelle-e2eviv"

# Working directory inside container
WORKDIR="/work"

# Volume mapping. We map the current directory.
VOLUME="$PWD:$WORKDIR"

# Print an informative message about volume mapping.
echo "Mapping current folder to $WORKDIR inside the container."

# Run container interactively and automatically destroy it when exiting.
"$DOCKER_CMD" run -it --rm -v "$VOLUME" -w "$WORKDIR" "$IMAGE"
