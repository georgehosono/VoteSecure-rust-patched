# Repository Docker Images

This directory contains the Docker image definitions and helper scripts used by the repository's CI/CD/CV workflows.

## Contents

The current images are:

- [`cpv-e2eviv/`](./cpv-e2eviv/) — cryptographic protocol verification tooling (Tamarin, Maude, Yices2, Graphviz)
- [`de-ple-e2eviv/`](./de-ple-e2eviv/) — domain engineering / product-line engineering tooling (Lando, Clafer, Chocosolver, `claferIG`, PlantUML, and related web-based tools)
- [`isabelle-e2eviv/`](./isabelle-e2eviv/) — Isabelle/HOL theorem-proving and document-building environment

## Top-level Makefile

The [`Makefile`](./Makefile) in this directory is an aggregator for the image-specific Makefiles. It supports:

```text
make help           # show available targets
make pull           # pull all repository Docker images
make build          # build all repository Docker images locally
make push           # push all repository Docker images to Docker Hub
make estimate-space # empirically measure local Docker storage usage while building
make clean          # run delegated clean targets for all image directories
```

The main optional overrides are:

- `DOCKER=<docker|podman>`
- `IMAGE_PLATFORM=<platform or comma-separated list>`
- `TARGETS='<space-separated image dirs>'` (for `make estimate-space`)
- `PRUNE=<yes|no>` (for `make estimate-space`)

For image-specific details, prerequisites, runtime notes, and known limitations, see the `README.md` in each subdirectory.
