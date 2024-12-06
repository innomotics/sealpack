# Change these variables as necessary.
MAIN_PACKAGE_PATH := ./cmd/
BUILD_DIR ?= .
BINARY_NAME := sealpack

default_target: build

# ==================================================================================== #
# HELPERS
# ==================================================================================== #

## help: print this help message
.PHONY: help
help:
	@echo 'Usage:'
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' |  sed -e 's/^/ /'

.PHONY: confirm
confirm:
	@echo -n 'Are you sure? [y/N] ' && read ans && [ $${ans:-N} = y ]

.PHONY: no-dirty
no-dirty:
	git diff --exit-code

# ==================================================================================== #
# QUALITY CONTROL
# ==================================================================================== #

## tidy: format code and tidy modfile
.PHONY: tidy
tidy:
	go fmt ./...
	go mod tidy -v

## audit: run quality control checks
.PHONY: audit
audit:
	go mod verify
	go vet ./...
	go run honnef.co/go/tools/cmd/staticcheck@latest ./...
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...
	go test -race -buildvcs -vet=off ./...


# ==================================================================================== #
# DEVELOPMENT
# ==================================================================================== #

## build: build the application
.PHONY: build
build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o=${BUILD_DIR}/${BINARY_NAME} ${MAIN_PACKAGE_PATH}


## install: install the application
.PHONY: install
install:
	install -d $(DESTDIR)/usr/sbin/
	install -m 755 ${BUILD_DIR}/${BINARY_NAME} $(DESTDIR)/usr/sbin/

# ==================================================================================== #
# OPERATIONS
# ==================================================================================== #

## push: push changes to the remote Git repository
.PHONY: push
push: tidy audit no-dirty
	git push

# ==================================================================================== #
# CLEANUP
# ==================================================================================== #

## clean: cleanup local worktree
.PHONY: clean
clean:
	go clean
