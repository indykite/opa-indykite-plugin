GO111MODULE=on

.PHONY: test

docker-build:
	@docker build -t indykite/opa:latest .

fmt:
	@echo "==> Fixing source code with gofmt..."
	gofmt -s -w .

goimports: gci

gci:
	@echo "==> Fixing imports code with gci..."
	gci write -s standard -s default -s "prefix(github.com/indykite/opa-indykite-plugin)" -s blank -s dot .

lint:
	@echo "==> Checking source code against linters..."
	golangci-lint run --timeout 2m0s ./...

install-tools:
	@echo Installing tools
	@go install github.com/daixiang0/gci@latest
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.54.1
	@go install github.com/onsi/ginkgo/v2/ginkgo@latest
	@echo Installation completed

test:
	go test -v -cpu 4 -covermode=count -coverpkg github.com/indykite/opa-indykite-plugin/... -coverprofile=coverage.out ./...

upgrade:
	@echo "==> Upgrading"
	@GO111MODULE=on go get -u all && go mod tidy
	@echo "==> Upgrading pre-commit"
	@pre-commit autoupdate

tidy:
	@GO111MODULE=on go mod tidy

opa-ci:
	@docker buildx create --name opabuilder --use
	@docker buildx build --push \
		--platform linux/amd64,linux/arm64 \
 		-t indykite/opa:latest \
 		-t indykite/opa:$(VERSION) \
 		-t $(GCR_URL)/$(GCP_PROJECT_ID)/jarvis/opa:test \
 		-t $(GCR_URL)/$(GCP_PROJECT_ID)/jarvis/opa:$(SHORT_SHA) \
 		--build-arg SHORT_SHA=$(SHORT_SHA) \
 		--build-arg TAG_NAME=$(VERSION) \
 		--build-arg BUILD_DATE=$(NOW) \
 		--build-arg TAG_NAME=$(GITHUB_REF) \
 		.
# TODO replace the block above after the migration to new GCP project		
	@docker buildx build --push \
		--platform linux/amd64,linux/arm64 \
		-t indykite/opa:latest \
		-t indykite/opa:$(VERSION) \
		-t $(ARTIFACT_REGISTRY_URL)/$(GCP_PROJECT_ID_MGMT)/indykite/opa:test \
		-t $(ARTIFACT_REGISTRY_URL)/$(GCP_PROJECT_ID_MGMT)/indykite/opa:$(SHORT_SHA) \
		--build-arg SHORT_SHA=$(SHORT_SHA) \
		--build-arg TAG_NAME=$(VERSION) \
		--build-arg BUILD_DATE=$(NOW) \
		--build-arg TAG_NAME=$(GITHUB_REF) \
		.
	@docker buildx rm opabuilder
