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

download:
	@echo Download go.mod dependencies
	@go mod download

install-tools: download
	@echo Installing tools from tools.go
	@go install $$(go list -f '{{range .Imports}}{{.}} {{end}}' tools.go)

test:
	go test -v -cpu 4 -covermode=count -coverpkg github.com/indykite/opa-indykite-plugin/... -coverprofile=coverage.out ./...

upgrade:
	@echo "==> Upgrading"
	@GO111MODULE=on go get -u all && go mod tidy

tidy:
	@GO111MODULE=on go mod tidy

opa-ci:
	@docker build -t indykite/opa:latest --build-arg SHORT_SHA=$(SHORT_SHA) --build-arg TAG_NAME=$(VERSION) --build-arg BUILD_DATE=$(NOW) --build-arg TAG_NAME=$(GITHUB_REF) .
	@docker tag indykite/opa $(GCR_URL)/$(GCP_PROJECT_ID)/jarvis/opa
	@docker tag indykite/opa $(GCR_URL)/$(GCP_PROJECT_ID)/jarvis/opa:$(SHORT_SHA)
	@docker tag indykite/opa indykite/opa:$(VERSION)
