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

package utils

import (
	"encoding/json"
	"os"
	"path/filepath"
)

const (
	DEFAULT_PREFERENCES_FILENAME = "preferences.json"
	DEFAULT_EDITOR_FONT_FAMILY   = "ui-monospace, \"Cascadia Code\", \"Fira Code\", Consolas, \"Courier New\", monospace"
	DEFAULT_EDITOR_FONT_SIZE     = 13
)

// UIPreferences contains preferences used by GUI renderers.
type UIPreferences struct {
	DefaultBomDirectory string `json:"defaultBomDirectory,omitempty"`
	EditorFontFamily    string `json:"editorFontFamily,omitempty"`
	EditorFontSize      int    `json:"editorFontSize,omitempty"`
	AutoValidateOnLoad  bool   `json:"autoValidateOnLoad"`
}

// CLIPreferences contains optional default configurations for CLI execution.
type CLIPreferences struct {
	ConfigSchemaFile        string `json:"configSchema,omitempty"`
	ConfigLicensePolicyFile string `json:"configLicense,omitempty"`
	OutputFormat            string `json:"outputFormat,omitempty"`
}

// AppPreferences represents the unified preferences schema for sbom-utility.
// It also supports flat top-level fields for backwards-compatibility.
type AppPreferences struct {
	UI  UIPreferences  `json:"ui"`
	CLI CLIPreferences `json:"cli"`

	// Flat compatibility fields for backwards-compatibility
	DefaultBomDirectory string `json:"defaultBomDirectory,omitempty"`
	EditorFontFamily    string `json:"editorFontFamily,omitempty"`
	EditorFontSize      int    `json:"editorFontSize,omitempty"`
	AutoValidateOnLoad  *bool  `json:"autoValidateOnLoad,omitempty"`
	ConfigSchema        string `json:"configSchema,omitempty"`
	ConfigLicense       string `json:"configLicense,omitempty"`
}

// PreferencesResult encapsulates loaded preferences with provenance metadata.
type PreferencesResult struct {
	Path        string         `json:"path"`
	Exists      bool           `json:"exists"`
	Preferences AppPreferences `json:"preferences"`
}

// DefaultAppPreferences returns the default built-in application preferences.
func DefaultAppPreferences() AppPreferences {
	return AppPreferences{
		UI: UIPreferences{
			EditorFontFamily:   DEFAULT_EDITOR_FONT_FAMILY,
			EditorFontSize:     DEFAULT_EDITOR_FONT_SIZE,
			AutoValidateOnLoad: true,
		},
		CLI: CLIPreferences{},
	}
}

// Normalize ensures nested and flat fields are synchronized with proper defaults.
func (p *AppPreferences) Normalize() {
	// Sync UI flat -> nested if nested is empty
	if p.UI.DefaultBomDirectory == "" && p.DefaultBomDirectory != "" {
		p.UI.DefaultBomDirectory = p.DefaultBomDirectory
	}
	if p.UI.EditorFontFamily == "" {
		if p.EditorFontFamily != "" {
			p.UI.EditorFontFamily = p.EditorFontFamily
		} else {
			p.UI.EditorFontFamily = DEFAULT_EDITOR_FONT_FAMILY
		}
	}
	if p.UI.EditorFontSize <= 0 {
		if p.EditorFontSize > 0 {
			p.UI.EditorFontSize = p.EditorFontSize
		} else {
			p.UI.EditorFontSize = DEFAULT_EDITOR_FONT_SIZE
		}
	}
	if p.AutoValidateOnLoad != nil {
		p.UI.AutoValidateOnLoad = *p.AutoValidateOnLoad
	}

	// Sync CLI flat -> nested
	if p.CLI.ConfigSchemaFile == "" && p.ConfigSchema != "" {
		p.CLI.ConfigSchemaFile = p.ConfigSchema
	}
	if p.CLI.ConfigLicensePolicyFile == "" && p.ConfigLicense != "" {
		p.CLI.ConfigLicensePolicyFile = p.ConfigLicense
	}

	// Mirror nested -> flat for JSON consumers that expect flat fields
	p.DefaultBomDirectory = p.UI.DefaultBomDirectory
	p.EditorFontFamily = p.UI.EditorFontFamily
	p.EditorFontSize = p.UI.EditorFontSize
	autoValidate := p.UI.AutoValidateOnLoad
	p.AutoValidateOnLoad = &autoValidate
	p.ConfigSchema = p.CLI.ConfigSchemaFile
	p.ConfigLicense = p.CLI.ConfigLicensePolicyFile
}

// LoadPreferencesFromWorkingDir loads preferences.json from the current working directory,
// falling back to built-in defaults if the file does not exist.
func LoadPreferencesFromWorkingDir() PreferencesResult {
	prefPath := filepath.Join(".", DEFAULT_PREFERENCES_FILENAME)
	absPath, err := filepath.Abs(prefPath)
	if err != nil {
		absPath = prefPath
	}

	result := PreferencesResult{
		Path:        absPath,
		Exists:      false,
		Preferences: DefaultAppPreferences(),
	}

	if _, statErr := os.Stat(prefPath); statErr == nil {
		data, readErr := os.ReadFile(prefPath)
		if readErr == nil {
			var loaded AppPreferences
			if jsonErr := json.Unmarshal(data, &loaded); jsonErr == nil {
				loaded.Normalize()
				result.Exists = true
				result.Preferences = loaded
				return result
			}
		}
	}

	result.Preferences.Normalize()
	return result
}
