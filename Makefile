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
BINARY=sbom-utility

# LDFLAG values
VERSION=latest
BUILD=`git rev-parse HEAD`
BUILD_DATE=`date -u +"%Y-%m-%dT%H:%M:%SZ"`
RELEASE_DIR=release

# TODO: automate other flags
# LDFLAGS=-ldflags "-X main.Version=${VERSION} -X main.GitCommit=${BUILD} -X main.BuildDate=${BUILD_DATE} -X main.Build=`git rev-parse HEAD` "
LDFLAGS=-ldflags "-X main.Version=${VERSION} -X main.Binary=${BINARY}"

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
release: clean config
	GOOS=darwin GOARCH=amd64 go build ${LDFLAGS} -o ${RELEASE_DIR}/sbom-utility-darwin-amd64
	GOOS=darwin GOARCH=arm64 go build ${LDFLAGS} -o ${RELEASE_DIR}/sbom-utility-darwin-arm64
	GOOS=linux GOARCH=amd64 go build ${LDFLAGS} -o ${RELEASE_DIR}/sbom-utility-linux-amd64
	GOOS=linux GOARCH=arm64 go build ${LDFLAGS} -o ${RELEASE_DIR}/sbom-utility-linux-arm64
	GOOS=windows GOARCH=amd64 go build ${LDFLAGS} -o ${RELEASE_DIR}/sbom-utility-windows-amd64
	GOOS=windows GOARCH=arm64 go build ${LDFLAGS} -o ${RELEASE_DIR}/sbom-utility-windows-arm64
	cp config.json ${RELEASE_DIR}/
	cp license.json ${RELEASE_DIR}/
	cp custom.json ${RELEASE_DIR}/

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
