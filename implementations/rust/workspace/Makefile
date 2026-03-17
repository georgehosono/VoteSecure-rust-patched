############################################################
# Rust workspace orchestration Makefile, © Free & Fair     #
############################################################

SHELL := /bin/bash

RUST_MANIFEST := Cargo.toml

.PHONY: default help ci cv ensure-tools update-tools

default: help

help:
	@echo "Rust workspace targets:"
	@echo ""
	@echo "help (default) - display this help page"
	@echo "ci             - run Rust CI checks (fmt/check/clippy/deny/build)"
	@echo "cv             - run Rust CV checks (tests)"
	@echo "ensure-tools   - install required tools if missing"
	@echo "update-tools   - force-update Rust CI tooling"

ensure-tools:
	@set -euo pipefail; \
	if command -v cargo-deny >/dev/null 2>&1; then \
		echo "[info] cargo-deny found"; \
	else \
		echo "[info] cargo-deny not found; installing"; \
		cargo install --locked cargo-deny; \
	fi

update-tools:
	@echo "[info] force-updating cargo-deny"
	@cargo install --locked cargo-deny --force

ci: ensure-tools
	@echo "[info] running Rust workspace checks"
	@cargo fmt --check --all --manifest-path $(RUST_MANIFEST)
	@cargo check --manifest-path $(RUST_MANIFEST)
	@cargo clippy --manifest-path $(RUST_MANIFEST)
	@cargo deny --workspace --manifest-path $(RUST_MANIFEST) check bans advisories sources
	@cargo build --release --manifest-path $(RUST_MANIFEST)

cv:
	@echo "[info] running Rust workspace tests"
	@cargo test --release --manifest-path $(RUST_MANIFEST) -- --test-threads=1
