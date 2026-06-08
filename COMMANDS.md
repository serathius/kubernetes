# Repository Command Mappings (kubernetes)

This document maps abstract development workflows (testing, building, linting, formatting) to specific `kubernetes` repository commands. Use these commands when generic instructions in `SKILL.md` files refer to these workflows.

## Validation & Linting
* **Full Validation Pipeline**: `make verify` (runs all checks)
* **Style/Lint Check**: `hack/verify-golangci-lint.sh`
* **Mod Tidy/Vendor Check**: `hack/verify-vendor.sh` (Note: Never use `go mod tidy` directly)
* **Go Formatting Check**: `hack/verify-gofmt.sh`
* **Shell Lint Check**: `hack/verify-shellcheck.sh`

## Automatic Fixes
* **Update All (Generators, formatters, vendor)**: `make update`
* **Fix Mod Tidy/Vendor**: `hack/update-vendor.sh`
* **Fix Go Formatting**: `hack/update-gofmt.sh`

## Testing & Deflaking
* **Unit Tests**: `make test` (or `make test WHAT=./pkg/kubelet GOFLAGS=-v` for a specific package)
* **Integration Tests**: `make test-integration` (or `make test-integration WHAT=./test/integration/scheduler` for a specific package)
* **End-to-End Tests (Node)**: `make test-e2e-node` (for node e2e tests)
