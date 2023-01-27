#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

SOURCEDIR=.

SOURCES := $(shell find $(SOURCEDIR) -name '*.go')
BINARY?=sbom-utility

# LDFLAG values
VERSION?=latest
BUILD=`git rev-parse HEAD`
BUILD_DATE=`date -u +"%Y-%m-%dT%H:%M:%SZ"`
RELEASE_DIR=release

# TODO: automate other flags
# LDFLAGS=-ldflags "-X main.Version=${VERSION} -X main.GitCommit=${BUILD} -X main.BuildDate=${BUILD_DATE} -X main.Build=`git rev-parse HEAD` "
# NOTE: The `-s` (sign) flag MUST be used or the binary will will be rejected on MacOS
# Additionally on MacOS, the binary MUST be moved (i.e., `mv`) not copied (i.e., `cp`)
LDFLAGS=-ldflags "-X main.Version=${VERSION} -X main.Binary=${BINARY} -s"

# Build the project
build: clean
	go build ${LDFLAGS} -o ${BINARY}

# General supported environments: https://go.dev/doc/install/source#environment
# See latest supported combinations using:
# $ go install golang.org/x/tools/cmd/goimports@latest
# $ go tool dist list
# However, many combinations are not supported "in box"
# See this Gist for details: https://gist.github.com/asukakenji/f15ba7e588ac42795f421b48b8aede63
# TODO: perhaps create universal binaries for various OS
# TODO: See "lipo" tool for MacOS universal binary
release: clean config sbom
	GOOS=darwin GOARCH=amd64 go build ${LDFLAGS} -o ${RELEASE_DIR}/${BINARY}-darwin-amd64
	GOOS=darwin GOARCH=arm64 go build ${LDFLAGS} -o ${RELEASE_DIR}/${BINARY}-darwin-arm64
	GOOS=linux GOARCH=amd64 go build ${LDFLAGS} -o ${RELEASE_DIR}/${BINARY}-linux-amd64
	GOOS=linux GOARCH=arm64 go build ${LDFLAGS} -o ${RELEASE_DIR}/${BINARY}-linux-arm64
	GOOS=windows GOARCH=amd64 go build ${LDFLAGS} -o ${RELEASE_DIR}/${BINARY}-windows-amd64
	GOOS=windows GOARCH=arm64 go build ${LDFLAGS} -o ${RELEASE_DIR}/${BINARY}-windows-arm64
	GOOS=windows GOARCH=arm64 go build ${LDFLAGS} -o ${RELEASE_DIR}/${BINARY}-windows-arm64
	GOOS=linux GOARCH=ppc64 go build ${LDFLAGS} -o ${RELEASE_DIR}/${BINARY}-linux-ppc64
	GOOS=linux GOARCH=s390x go build ${LDFLAGS} -o ${RELEASE_DIR}/${BINARY}-linux-s390x
	cp config.json ${RELEASE_DIR}/
	cp license.json ${RELEASE_DIR}/
	cp custom.json ${RELEASE_DIR}/

sbom:
	@echo "Creating Software-Bill-Of-Materials (CycloneDX latest JSON format)"
	go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest
	mkdir -p ${RELEASE_DIR}
	cyclonedx-gomod mod -json=true -output ${RELEASE_DIR}/${BINARY}-${VERSION}.bom.json .

# Clean test cache
test_clean:
	go clean -testcache

# Run all tests
test: test_clean
	@echo "Testing"
	go test ./... -v

# Run cmd tests
test_cmd: test_clean
	@echo "Testing `cmd` package"
	go test ./cmd -v --args --quiet

# Run the unit tests
unit_tests: test_clean
	@echo "Testing -tags=unit"
	go test ./... -v -tags=unit

# Run the integration tests
integration_tests:
	@echo "Testing -tags=integration"
	go test -v ./... -tags=integration

format:
	@echo "Formatting"
	go fmt ./...

lint: format
	@echo "Linting"
	golint .

install:
	go install

# Cleans project up binaries
# if ${BINARY}: covers any manual `go build` executables
# if ${BINARY}: covers `make build` target
# if ${RELEASE_DIR}: covers `make release` target
clean:
	@if [ -f ${BINARY} ] ; then rm ${BINARY} ; fi
	@if [ -d ${RELEASE_DIR} ] ; then rm -f ${RELEASE_DIR}/${BINARY}* ; rm -f ${RELEASE_DIR}/*.json ; rmdir ${RELEASE_DIR} ; fi

.PHONY: config clean build release test_clean test test_cmd unit_tests integration_tests format lint install
