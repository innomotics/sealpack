# Change these variables as necessary.
MAIN_PACKAGE_PATH := ./cmd/
BUILD_DIR ?= .
GOARCH ?= amd64
BINARY_NAME := sealpack
DEBIAN_DIR := $(shell pwd)/debian
DOCKER := podman
FPM_IMAGE := registry.alm.innomotics.net/in/shared/clearing/automation/fpm:latest

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

.PHONY: upgrade-dependencies
upgrade-dependencies:
	go get -u all
	go mod tidy -v
	go test ./...

# ==================================================================================== #
# QUALITY CONTROL
# ==================================================================================== #

## tidy: format code and tidy modfile
.PHONY: tidy
tidy:
	go fmt ./...
	go mod tidy -v
	go test ./...

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
build: build-arm64 build-amd64

## build: build the application
.PHONY: build-%
build-%:
	CGO_ENABLED=0 GOOS=linux GOARCH=$* go build -ldflags="-w -s" -o=${BUILD_DIR}/${BINARY_NAME} ${MAIN_PACKAGE_PATH}

.PHONY: debian
debian: debian-arm64 debian-amd64

.PHONY: debian-%
debian-%: build-%
	@mkdir -p $(DEBIAN_DIR)/{src,out}
	@cp ${BUILD_DIR}/${BINARY_NAME} $(DEBIAN_DIR)/src
	$(DOCKER) run -v $(DEBIAN_DIR)/src:/src \
				-v $(DEBIAN_DIR)/out:/out \
  				-it $(FPM_IMAGE) \
  				-s dir \
  				-t deb \
  				--name sealpack \
  				--license apache2.0 \
  				--version $(shell git describe --abbrev=0) \
  				--architecture $(if $(filter-out amd64,$*),$*,x86_64) \
  				--description "Sealed packaging for files and containers" \
  				--url "https://github.com/innomotics/sealpack" \
  				--maintainer "Mathias Haimerl <mathias.haimerl@innomotics.com>" \
  				/src/sealpack=/usr/bin/sealpack
	@rm $(DEBIAN_DIR)/src/${BINARY_NAME}

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
