SHELL         := /bin/bash
.SHELLFLAGS   := -eu -o pipefail -c

APP_NAME 	   := pgrwl
OUTPUT   	   := $(APP_NAME)
OUTPUT_UI    := pgrwl-ui
COV_REPORT 	 := coverage.txt
INSTALL_DIR  := /usr/local/bin

ifeq ($(OS),Windows_NT)
	OUTPUT := $(APP_NAME).exe
endif

######################################################################
### basic targets
######################################################################

.PHONY: gen
gen: ## Run go generate
	go generate ./...

.PHONY: build
build: gen ## Build the binary
	CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/$(OUTPUT) cmd/pgrwl/main.go

.PHONY: build-linux
build-linux: gen ## Build the binary (linux)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/pgrwl cmd/pgrwl/main.go

.PHONY: lint
lint: ## Run golangci-lint
	golangci-lint run --output.tab.path=stdout

.PHONY: install
install: build ## Install the binary to $(INSTALL_DIR)
	@echo "Installing bin/$(OUTPUT) to $(INSTALL_DIR)..."
	@sudo chmod +x bin/$(OUTPUT) && sudo cp bin/$(OUTPUT) $(INSTALL_DIR)

.PHONY: snapshot
snapshot: ## Run snapshot build with goreleaser
	GORELEASER_FORCE_TOKEN=github goreleaser release --skip sign --skip publish --snapshot --clean

.PHONY: test
test: ## Run unit tests
	go test -v -race -cover -timeout 5m ./...

.PHONY: test-cov
test-cov: ## Run tests with coverage report
	go test -coverprofile=$(COV_REPORT) ./...
	go tool cover -html=$(COV_REPORT)

.PHONY: image
image: ## Build and push Docker image to localhost:5000
	docker buildx build -t localhost:5000/pgrwl .
	docker push localhost:5000/pgrwl

######################################################################
### integration tests
######################################################################

.PHONY: test-integ-scripts-17
test-integ-scripts-17: ## Slow tests (that runs inside containers)
	@cd test/integration/environ && PG_MAJOR=17 bash run-tests.sh | tee $(CURDIR)/test-integ-scripts-17.log

.PHONY: test-integ-scripts-18
test-integ-scripts-18: ## Slow tests (that runs inside containers)
	@cd test/integration/environ && PG_MAJOR=18 bash run-tests.sh | tee $(CURDIR)/test-integ-scripts-18.log

.PHONY: test-integ-par-17
test-integ-par-17: ## Run integration script-tests in parallel (PG17)
	@cd test/integration/environ && BUILD=1 PG_MAJOR=17 bash run-tests-par.sh

.PHONY: test-integ-par-18
test-integ-par-18: ## Run integration script-tests in parallel (PG18)
	@cd test/integration/environ && BUILD=1 PG_MAJOR=18 bash run-tests-par.sh

######################################################################
### profiling
######################################################################

.PHONY: run
run: build ## Run the binary with local config
	export PGHOST="localhost" && \
	export PGPORT="5432" && \
	export PGUSER="postgres" && \
	export PGPASSWORD="postgres" && \
	bin/$(OUTPUT) daemon -c hack/configs/localfs/receive.yml

.PHONY: profile-cpu
profile-cpu: ## Capture CPU profile and open web UI
	nohup bash hack/scripts/switch-wals-25.sh &
	go tool pprof -http=: http://localhost:7070/debug/pprof/profile?seconds=20

.PHONY: pprof1
pprof1: ## Collect allocs, heap, CPU, and trace profiles
	nohup bash hack/scripts/switch-wals-25.sh &
	go tool pprof -web http://127.0.0.1:7070/debug/pprof/allocs
	go tool pprof -web http://127.0.0.1:7070/debug/pprof/heap
	go tool pprof -web http://127.0.0.1:7070/debug/pprof/profile?seconds=10
	curl -s http://127.0.0.1:7070/debug/pprof/trace\?seconds\=10 | go tool trace /dev/stdin

######################################################################
### storage integration tests
######################################################################

.PHONY: test-integ-storage
test-integ-storage: ## Integration tests for storage layer only
	@cd test/integration/storage/environ && bash run.sh
	go test -tags=integration_storage -v ./test/integration/storage/... | tee test-integ-storage.log

.PHONY: test-integ-storage-highload
test-integ-storage-highload:
	@cd test/integration/storage/environ && bash run.sh
	go test -tags=integration_storage_highload -v ./test/integration/storage/... | tee test-integ-storage-highload.log

.PHONY: test-integ-storage-teardown
test-integ-storage-teardown:
	@cd test/integration/storage/environ && bash teardown.sh

######################################################################
### UI related
######################################################################

.PHONY: build-ui
build-ui: ## Build UI binary
	CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/$(OUTPUT_UI) cmd/pgrwl-ui/main.go

.PHONY: build-linux-ui
build-linux-ui: ## Build UI binary (linux)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/pgrwl-ui cmd/pgrwl-ui/main.go

.PHONY: image-ui
image-ui: ## Build and push Docker image to localhost:5000
	docker buildx build -t localhost:5000/pgrwl-ui -f Dockerfile-ui .
	docker push localhost:5000/pgrwl-ui

######################################################################
### various tags based integration tests
######################################################################

.PHONY: test-integ-localdev
test-integ-localdev:
	@cd test/integration/localdev/environ && bash run.sh
	go test -tags=integration_localdev -v ./test/integration/localdev/... | tee test-integ-localdev.log

######################################################################
### k8s related integration tests (CI oriented)
######################################################################

.PHONY: test-integ-k8s-ci
test-integ-k8s-ci:
	@cd test/integration/k8s-ci && bash run.sh

######################################################################
### common
######################################################################

.PHONY: clean
clean: ## Remove build artifacts and logs
	@rm -rf bin/ dist/ test/integration/environ/bin/
	@find -type f -name '*.log' -delete

.PHONY: help
help: ## Show this help
	@echo "Usage: make <target>"
	@echo ""
	@echo "Available targets:"
	@grep -E '^[a-zA-Z0-9_.-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-24s\033[0m %s\n", $$1, $$2}'
