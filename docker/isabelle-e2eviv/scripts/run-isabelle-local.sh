#!/bin/bash
set -e # exit immediately upon error(s)

# Name of the docker image to run
IMAGE="isabelle-e2eviv"

# Working directory inside container
WORKDIR="/work"

# Volume mapping. We map the current directory.
VOLUME="$PWD:$WORKDIR"

# Print an informative message about volume mapping.
echo "Mapping current folder to /work inside the container."

# Run container interactively and automatically destroy it when exiting.
docker run -it --rm -v "$VOLUME" -w "$WORKDIR" $IMAGE
