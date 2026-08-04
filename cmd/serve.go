// SPDX-License-Identifier: Apache-2.0
/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/CycloneDX/sbom-utility/common"
	"github.com/CycloneDX/sbom-utility/utils"
	"github.com/spf13/cobra"
)

const (
	FLAG_SERVE_PORT      = "port"
	DEFAULT_SERVE_PORT   = 8787
	serveAPIPrefix       = "/api"
	serveOpenDialogPath  = "/open"
	serveReadFilePath    = "/read"
	serveWriteFilePath   = "/write"
	serveBomInfoPath     = "/bom-info"
	serveValidatePath    = "/validate"
	serveLicenseListPath = "/license/list"
	serveComponentPath   = "/component/list"
	serveResourcePath    = "/resource/list"
	serveVulnPath        = "/vulnerability/list"
	serveDiffPath        = "/diff"
	servePatchPath       = "/patch"
)

type serveRunResult struct {
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
	Code   int    `json:"code"`
}

type serveFileRequest struct {
	FilePath string `json:"filePath"`
}

type serveWriteFileRequest struct {
	FilePath string `json:"filePath"`
	Content  string `json:"content"`
}

type serveOpenFileResponse struct {
	FilePath string `json:"filePath"`
	Content  string `json:"content"`
}

type serveBomInfoResponse struct {
	FilePath    string `json:"filePath"`
	SpecVersion string `json:"specVersion"`
	Format      string `json:"format"`
}

type serveValidateRequest struct {
	FilePath    string `json:"filePath"`
	Variant     string `json:"variant"`
	ForceSchema string `json:"forceSchema"`
	MaxErrors   int    `json:"maxErrors"`
	ShowValues  bool   `json:"showValues"`
}

type serveListRequest struct {
	FilePath     string `json:"filePath"`
	Format       string `json:"format"`
	Where        string `json:"where"`
	Summary      bool   `json:"summary"`
	ResourceType string `json:"resourceType"`
}

type serveDiffRequest struct {
	FileA string `json:"fileA"`
	FileB string `json:"fileB"`
}

type servePatchRequest struct {
	BomPath   string `json:"bomPath"`
	PatchPath string `json:"patchPath"`
}

func NewCommandServe() *cobra.Command {
	var port int
	command := new(cobra.Command)
	command.Use = CMD_USAGE_SERVE
	command.Short = "Serve a localhost HTTP API for the browser GUI"
	command.Long = "Serve a localhost HTTP API for the browser GUI"
	command.Flags().IntVarP(&port, FLAG_SERVE_PORT, "", DEFAULT_SERVE_PORT, "localhost port for the browser GUI API")
	command.RunE = func(cmd *cobra.Command, args []string) error {
		return Serve(port)
	}
	return command
}

func Serve(port int) error {
	mux := http.NewServeMux()
	mux.HandleFunc(serveAPIPrefix+serveOpenDialogPath, handleServeOpenFile)
	mux.HandleFunc(serveAPIPrefix+serveReadFilePath, handleServeReadFile)
	mux.HandleFunc(serveAPIPrefix+serveWriteFilePath, handleServeWriteFile)
	mux.HandleFunc(serveAPIPrefix+serveBomInfoPath, handleServeBomInfo)
	mux.HandleFunc(serveAPIPrefix+serveValidatePath, handleServeValidate)
	mux.HandleFunc(serveAPIPrefix+serveLicenseListPath, handleServeLicenseList)
	mux.HandleFunc(serveAPIPrefix+serveComponentPath, handleServeComponentList)
	mux.HandleFunc(serveAPIPrefix+serveResourcePath, handleServeResourceList)
	mux.HandleFunc(serveAPIPrefix+serveVulnPath, handleServeVulnerabilityList)
	mux.HandleFunc(serveAPIPrefix+serveDiffPath, handleServeDiff)
	mux.HandleFunc(serveAPIPrefix+servePatchPath, handleServePatch)

	addr := "127.0.0.1:" + strconvItoa(port)
	getLogger().Infof("Starting browser GUI API server on http://%s", addr)
	return http.ListenAndServe(addr, withCORS(mux))
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Access-Control-Allow-Origin", "*")
		writer.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if request.Method == http.MethodOptions {
			writer.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func handleServeOpenFile(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeServeMethodNotAllowed(writer)
		return
	}

	if err := request.ParseMultipartForm(32 << 20); err != nil {
		writeServeError(writer, http.StatusBadRequest, err)
		return
	}

	file, header, err := request.FormFile("file")
	if err != nil {
		writeServeError(writer, http.StatusBadRequest, err)
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		writeServeError(writer, http.StatusInternalServerError, err)
		return
	}

	tempDir, err := os.MkdirTemp("", "sbom-utility-gui-")
	if err != nil {
		writeServeError(writer, http.StatusInternalServerError, err)
		return
	}

	path := filepath.Join(tempDir, filepath.Base(header.Filename))
	if err = os.WriteFile(path, data, 0o600); err != nil {
		writeServeError(writer, http.StatusInternalServerError, err)
		return
	}

	writeServeJSON(writer, http.StatusOK, serveOpenFileResponse{
		FilePath: path,
		Content:  string(data),
	})
}

func handleServeReadFile(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeServeMethodNotAllowed(writer)
		return
	}

	var payload serveFileRequest
	if err := decodeServeJSON(request, &payload); err != nil {
		writeServeError(writer, http.StatusBadRequest, err)
		return
	}

	safePath, err := resolveServePath(payload.FilePath)
	if err != nil {
		writeServeError(writer, http.StatusBadRequest, err)
		return
	}

	data, err := os.ReadFile(safePath)
	if err != nil {
		writeServeError(writer, http.StatusBadRequest, err)
		return
	}

	writeServeJSON(writer, http.StatusOK, map[string]string{"content": string(data)})
}

func handleServeWriteFile(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeServeMethodNotAllowed(writer)
		return
	}

	var payload serveWriteFileRequest
	if err := decodeServeJSON(request, &payload); err != nil {
		writeServeError(writer, http.StatusBadRequest, err)
		return
	}

	safePath, err := resolveServePath(payload.FilePath)
	if err != nil {
		writeServeError(writer, http.StatusBadRequest, err)
		return
	}

	if err := os.WriteFile(safePath, []byte(payload.Content), 0o600); err != nil {
		writeServeError(writer, http.StatusBadRequest, err)
		return
	}

	writer.WriteHeader(http.StatusNoContent)
}

func handleServeBomInfo(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeServeMethodNotAllowed(writer)
		return
	}

	var payload serveFileRequest
	if err := decodeServeJSON(request, &payload); err != nil {
		writeServeError(writer, http.StatusBadRequest, err)
		return
	}

	safePath, err := resolveServePath(payload.FilePath)
	if err != nil {
		writeServeError(writer, http.StatusBadRequest, err)
		return
	}

	withServeInputFile(safePath, func() {
		document, err := LoadInputBOMFileAndDetectSchema()
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, err)
			return
		}

		writeServeJSON(writer, http.StatusOK, serveBomInfoResponse{
			FilePath:    safePath,
			SpecVersion: document.SchemaInfo.Version,
			Format:      document.FormatInfo.CanonicalName,
		})
	})
}

func handleServeValidate(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeServeMethodNotAllowed(writer)
		return
	}

	var payload serveValidateRequest
	if err := decodeServeJSON(request, &payload); err != nil {
		writeServeError(writer, http.StatusBadRequest, err)
		return
	}

	safePath, err := resolveServePath(payload.FilePath)
	if err != nil {
		writeServeError(writer, http.StatusBadRequest, err)
		return
	}
	payload.FilePath = safePath

	result, err := runServeValidate(payload)
	if err != nil {
		writeServeError(writer, http.StatusBadRequest, err)
		return
	}
	writeServeJSON(writer, http.StatusOK, result)
}

func handleServeLicenseList(writer http.ResponseWriter, request *http.Request) {
	handleServeListOperation(writer, request, runServeLicenseList)
}

func handleServeComponentList(writer http.ResponseWriter, request *http.Request) {
	handleServeListOperation(writer, request, runServeComponentList)
}

func handleServeResourceList(writer http.ResponseWriter, request *http.Request) {
	handleServeListOperation(writer, request, runServeResourceList)
}

func handleServeVulnerabilityList(writer http.ResponseWriter, request *http.Request) {
	handleServeListOperation(writer, request, runServeVulnerabilityList)
}

func handleServeDiff(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeServeMethodNotAllowed(writer)
		return
	}

	var payload serveDiffRequest
	if err := decodeServeJSON(request, &payload); err != nil {
		writeServeError(writer, http.StatusBadRequest, err)
		return
	}

	safeFileA, errA := resolveServePath(payload.FileA)
	safeFileB, errB := resolveServePath(payload.FileB)
	if errA != nil || errB != nil {
		writeServeError(writer, http.StatusBadRequest, fmt.Errorf("file path is not permitted"))
		return
	}
	payload.FileA = safeFileA
	payload.FileB = safeFileB

	result, err := runServeDiff(payload)
	if err != nil {
		writeServeError(writer, http.StatusBadRequest, err)
		return
	}
	writeServeJSON(writer, http.StatusOK, result)
}

func handleServePatch(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeServeMethodNotAllowed(writer)
		return
	}

	var payload servePatchRequest
	if err := decodeServeJSON(request, &payload); err != nil {
		writeServeError(writer, http.StatusBadRequest, err)
		return
	}

	safeBomPath, errBom := resolveServePath(payload.BomPath)
	safePatchPath, errPatch := resolveServePath(payload.PatchPath)
	if errBom != nil || errPatch != nil {
		writeServeError(writer, http.StatusBadRequest, fmt.Errorf("file path is not permitted"))
		return
	}
	payload.BomPath = safeBomPath
	payload.PatchPath = safePatchPath

	result, err := runServePatch(payload)
	if err != nil {
		writeServeError(writer, http.StatusBadRequest, err)
		return
	}
	writeServeJSON(writer, http.StatusOK, result)
}

func handleServeListOperation(writer http.ResponseWriter, request *http.Request, operation func(serveListRequest) (serveRunResult, error)) {
	if request.Method != http.MethodPost {
		writeServeMethodNotAllowed(writer)
		return
	}

	var payload serveListRequest
	if err := decodeServeJSON(request, &payload); err != nil {
		writeServeError(writer, http.StatusBadRequest, err)
		return
	}

	safePath, err := resolveServePath(payload.FilePath)
	if err != nil {
		writeServeError(writer, http.StatusBadRequest, err)
		return
	}
	payload.FilePath = safePath

	result, err := operation(payload)
	if err != nil {
		writeServeError(writer, http.StatusBadRequest, err)
		return
	}
	writeServeJSON(writer, http.StatusOK, result)
}

func runServeValidate(request serveValidateRequest) (serveRunResult, error) {
	result := serveRunResult{}
	withServeInputFile(request.FilePath, func() {
		// Write directly to the global flags so that FormatSchemaErrors (which
		// reads utils.GlobalFlags.ValidateFlags rather than its parameter) picks
		// up the correct values.
		utils.GlobalFlags.ValidateFlags.SchemaVariant = request.Variant
		utils.GlobalFlags.ValidateFlags.ForcedJsonSchemaFile = request.ForceSchema
		utils.GlobalFlags.ValidateFlags.ShowErrorValue = request.ShowValues
		if request.MaxErrors > 0 {
			utils.GlobalFlags.ValidateFlags.MaxNumErrors = request.MaxErrors
		} else {
			utils.GlobalFlags.ValidateFlags.MaxNumErrors = DEFAULT_MAX_ERROR_LIMIT
		}

		persistent := utils.GlobalFlags.PersistentFlags
		persistent.InputFile = request.FilePath
		persistent.OutputFormat = FORMAT_TEXT

		var stdout bytes.Buffer
		isValid, _, _, err := Validate(&stdout, persistent, utils.GlobalFlags.ValidateFlags)
		result.Stdout = stdout.String()
		if err != nil || !isValid {
			result.Code = ERROR_VALIDATION
		}
	})
	return result, nil
}

func runServeLicenseList(request serveListRequest) (serveRunResult, error) {
	return runServeListWithFilters(request, func(writer io.Writer, persistent utils.PersistentCommandFlags, whereFilters []common.WhereFilter) error {
		flags := utils.GlobalFlags.LicenseFlags
		flags.Summary = request.Summary
		return ListLicenses(writer, LicensePolicyConfig, persistent, flags, whereFilters)
	})
}

func runServeComponentList(request serveListRequest) (serveRunResult, error) {
	return runServeListWithFilters(request, func(writer io.Writer, persistent utils.PersistentCommandFlags, whereFilters []common.WhereFilter) error {
		flags := utils.GlobalFlags.ComponentFlags
		flags.Summary = request.Summary
		return ListComponents(writer, persistent, flags, whereFilters)
	})
}

func runServeResourceList(request serveListRequest) (serveRunResult, error) {
	return runServeListWithFilters(request, func(writer io.Writer, persistent utils.PersistentCommandFlags, whereFilters []common.WhereFilter) error {
		flags := utils.GlobalFlags.ResourceFlags
		flags.ResourceType = request.ResourceType
		return ListResources(writer, persistent, flags, whereFilters)
	})
}

func runServeVulnerabilityList(request serveListRequest) (serveRunResult, error) {
	return runServeListWithFilters(request, func(writer io.Writer, persistent utils.PersistentCommandFlags, whereFilters []common.WhereFilter) error {
		flags := utils.GlobalFlags.VulnerabilityFlags
		flags.Summary = request.Summary
		return ListVulnerabilities(writer, persistent, flags, whereFilters)
	})
}

func runServeListWithFilters(request serveListRequest, operation func(io.Writer, utils.PersistentCommandFlags, []common.WhereFilter) error) (serveRunResult, error) {
	result := serveRunResult{}
	whereFilters, err := retrieveWhereFilters(request.Where)
	if err != nil {
		return result, err
	}

	withServeInputFile(request.FilePath, func() {
		persistent := utils.GlobalFlags.PersistentFlags
		persistent.InputFile = request.FilePath
		persistent.OutputFormat = normalizeServeFormat(request.Format, FORMAT_TEXT)

		var stdout bytes.Buffer
		err = operation(&stdout, persistent, whereFilters)
		result.Stdout = stdout.String()
		if err != nil {
			result.Code = ERROR_APPLICATION
		}
	})

	return result, err
}

func runServeDiff(request serveDiffRequest) (serveRunResult, error) {
	result := serveRunResult{}
	persistent := utils.GlobalFlags.PersistentFlags
	persistent.InputFile = request.FileA
	flags := utils.GlobalFlags.DiffFlags
	flags.RevisedFile = request.FileB
	flags.OutputFormat = FORMAT_UNIFIED

	err := Diff(persistent, flags)
	if err != nil {
		result.Code = ERROR_APPLICATION
		return result, err
	}

	result.Stdout = readServeOutputFile(persistent.OutputFile)
	if result.Stdout == "" {
		result.Code = ERROR_APPLICATION
	}
	return result, nil
}

func runServePatch(request servePatchRequest) (serveRunResult, error) {
	result := serveRunResult{}
	persistent := utils.GlobalFlags.PersistentFlags
	persistent.InputFile = request.BomPath
	persistent.OutputFormat = FORMAT_JSON
	flags := utils.GlobalFlags.PatchFlags
	flags.PatchFile = request.PatchPath

	var stdout bytes.Buffer
	err := Patch(&stdout, persistent, flags)
	result.Stdout = stdout.String()
	if err != nil {
		result.Code = ERROR_APPLICATION
		return result, err
	}
	return result, nil
}

func decodeServeJSON(request *http.Request, value interface{}) error {
	defer request.Body.Close()
	return json.NewDecoder(request.Body).Decode(value)
}

func writeServeJSON(writer http.ResponseWriter, status int, value interface{}) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func writeServeError(writer http.ResponseWriter, status int, err error) {
	writeServeJSON(writer, status, map[string]string{"error": err.Error()})
}

func writeServeMethodNotAllowed(writer http.ResponseWriter) {
	writer.WriteHeader(http.StatusMethodNotAllowed)
}

func withServeInputFile(inputFile string, fn func()) {
	// Re-validate here so the assignment to GlobalFlags always uses a
	// canonicalised path, cutting any taint flow through global state.
	safe, err := resolveServePath(inputFile)
	if err != nil {
		return
	}
	saved := utils.GlobalFlags.PersistentFlags.InputFile
	utils.GlobalFlags.PersistentFlags.InputFile = safe
	defer func() {
		utils.GlobalFlags.PersistentFlags.InputFile = saved
	}()
	fn()
}

func normalizeServeFormat(value string, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func readServeOutputFile(path string) string {
	if path == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

func strconvItoa(value int) string {
	return strconv.Itoa(value)
}

// resolveServePath canonicalises path and ensures it is located inside the OS
// temp directory, preventing path-traversal attacks where a caller could supply
// an arbitrary filesystem path (e.g. "/etc/passwd" or "../../sensitive").
// It returns the cleaned absolute path so callers use the validated form.
func resolveServePath(path string) (string, error) {
	// Resolve ".." segments and make the path absolute so the comparison is reliable.
	resolved, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("invalid file path")
	}
	tmpDir, err := filepath.Abs(os.TempDir())
	if err != nil {
		return "", fmt.Errorf("invalid file path")
	}
	// The resolved path must be strictly inside the temp directory.
	if !strings.HasPrefix(resolved, tmpDir+string(filepath.Separator)) {
		return "", fmt.Errorf("file path is not permitted")
	}
	return resolved, nil
}
