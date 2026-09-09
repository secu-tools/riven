# Copyright (c) 2026 Jack L. (Cpt-JackL) (https://jack-l.com)
# SPDX-License-Identifier: MIT

.PHONY: build test test-short test-all integration e2e smoke fuzz coverage vet clean cross linux windows darwin

BINARY=riven
VERSION?=$(shell if [ -f version/version_base.txt ]; then head -1 version/version_base.txt | tr -cd '0-9.'; else echo "1.0.0"; fi)
COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")
BUILD_NUMBER_FILE=version/build_number.txt
BUILD_NUMBER=$(shell if [ -f $(BUILD_NUMBER_FILE) ]; then cat $(BUILD_NUMBER_FILE); else echo 0; fi)
NEXT_BUILD=$(shell echo $$(( $(BUILD_NUMBER) + 1 )))
FULL_VERSION=$(VERSION).$(NEXT_BUILD)
MODULE=github.com/secu-tools/riven/internal/app
LDFLAGS_BASE=-X $(MODULE).version=$(VERSION) -X $(MODULE).commit=$(COMMIT) -X $(MODULE).buildNumber=$(NEXT_BUILD) -s -w
BUILD_DIR=build

all: test build

build:
	@echo $(NEXT_BUILD) > $(BUILD_NUMBER_FILE)
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS_BASE)" -trimpath -o $(BINARY)_$(FULL_VERSION) ./

# Unit tests + fuzz seed corpus.
test:
	go test ./... -count=1

test-short:
	go test ./... -short -count=1

fuzz:
	go test -run '^Fuzz' -count=1 ./internal/...

integration:
	go test -tags integration -count=1 -timeout 180s ./tests/integration/

e2e:
	go test -tags e2e -count=1 -timeout 300s ./tests/e2e/

smoke:
	go test -tags smoke -count=1 -timeout 180s ./tests/smoke/

# Everything: unit -> integration -> e2e -> smoke.
test-all: test integration e2e smoke

coverage:
	go test ./... -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

vet:
	go vet ./...

clean:
	rm -f $(BINARY) $(BINARY).exe $(BINARY)_*
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

cross:
	bash ./build.sh -all

linux:
	bash ./build.sh -linux

windows:
	bash ./build.sh -windows

darwin:
	bash ./build.sh -darwin
