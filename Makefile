GO ?= go
.NOTPARALLEL: check
export CGO_ENABLED := 0

.PHONY: build test lint cross-compile check-size check-agent-surface check-panel-assets check-files check
build:
	@mkdir -p bin
	$(GO) build -trimpath -ldflags='-s -w' -o bin/wanglou-agent ./cmd/wanglou-agent
	$(GO) build -trimpath -ldflags='-s -w' -o bin/wanglou-server ./cmd/wanglou-server
test:
	$(GO) test ./...
lint:
	$(GO) vet ./...
cross-compile:
	@mkdir -p bin
	GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags='-s -w' -o bin/wanglou-agent-linux-amd64 ./cmd/wanglou-agent
	GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags='-s -w' -o bin/wanglou-server-linux-amd64 ./cmd/wanglou-server
	GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags='-s -w' -o bin/wanglou-agent-linux-arm64 ./cmd/wanglou-agent
	GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags='-s -w' -o bin/wanglou-server-linux-arm64 ./cmd/wanglou-server
check-size: cross-compile
	@for arch in amd64 arm64; do bytes=$$(wc -c < bin/wanglou-agent-linux-$$arch); echo "agent linux/$$arch: $$bytes bytes (limit 8000000)"; test "$$bytes" -le 8000000 || exit 1; done
check-agent-surface:
	@agent_deps=$$(mktemp); trap 'rm -f "$$agent_deps"' EXIT HUP INT TERM; \
	for target in darwin/arm64 linux/amd64 linux/arm64; do \
	  target_os=$${target%/*}; target_arch=$${target#*/}; \
	  GOOS=$$target_os GOARCH=$$target_arch $(GO) list -deps -json ./cmd/wanglou-agent ./internal/agent/... > "$$agent_deps" || exit 1; \
	  echo "checking $$target"; $(GO) run ./scripts/check-agent-surface < "$$agent_deps" || exit 1; \
	done
check-panel-assets:
	@$(GO) run ./scripts/check-panel-assets
check-files:
	@test -s README.md
	@for file in Dockerfile .dockerignore deploy/docker/compose.yml deploy/docker/backup.compose.yml deploy/docker/backup.Caddyfile deploy/docker/Caddyfile deploy/docker/.env.example deploy/docker/agent.compose.yml .github/workflows/ci.yml .github/workflows/docker.yml; do \
	  test -s "$$file" || exit 1; \
	done
	@grep -Fqx 'FROM gcr.io/distroless/static-debian12:nonroot AS server' Dockerfile
	@grep -Fqx 'FROM gcr.io/distroless/static-debian12:nonroot AS agent' Dockerfile
	@test "$$(grep -c '^USER 65532:65532$$' Dockerfile)" -eq 2
	@for unit in deploy/systemd/wanglou-agent.service deploy/systemd/wanglou-server.service; do \
	  for setting in 'User=wanglou' 'NoNewPrivileges=yes' 'ProtectSystem=strict' 'ProtectHome=yes' 'PrivateTmp=yes' 'PrivateDevices=yes' 'CapabilityBoundingSet=' 'RestrictAddressFamilies=AF_INET AF_INET6' 'SystemCallFilter=@system-service' 'Restart=always'; do \
	    grep -Fqx "$$setting" "$$unit" || exit 1; \
	  done; \
	done
	@grep -Fqx 'MemoryMax=24M' deploy/systemd/wanglou-agent.service
	@grep -Fqx 'CPUQuota=5%' deploy/systemd/wanglou-agent.service
	@grep -Fqx 'MemoryMax=256M' deploy/systemd/wanglou-server.service
	@! grep -q '^CPUQuota=' deploy/systemd/wanglou-server.service
	@grep -Fqx 'ReadWritePaths=/var/lib/wanglou' deploy/systemd/wanglou-server.service
	@if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then \
	  for compose in compose.yml backup.compose.yml; do \
	    DOMAIN=ingest.example.invalid PANEL_DOMAIN=panel.example.invalid PRIMARY_DOMAIN=primary.example.invalid docker compose -f deploy/docker/$$compose config -q || exit 1; \
	  done; \
	  echo 'docker compose config: PASS (primary and backup)'; \
	else echo 'docker compose config: SKIP (docker compose unavailable)'; fi
	@echo 'deployment files and README: PASS'
check: lint test cross-compile check-size check-agent-surface check-panel-assets check-files
