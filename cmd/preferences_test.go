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
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/CycloneDX/sbom-utility/utils"
)

func TestPreferencesPrecedence(t *testing.T) {
	// Create a temporary preferences.json file in current working directory
	tempPrefFile := filepath.Join(".", utils.DEFAULT_PREFERENCES_FILENAME)
	defer os.Remove(tempPrefFile)

	prefData := utils.AppPreferences{
		CLI: utils.CLIPreferences{
			ConfigLicensePolicyFile: "test/license/license-policy-test-empty.json",
		},
	}
	encoded, err := json.Marshal(prefData)
	if err != nil {
		t.Fatalf("failed to marshal pref: %v", err)
	}
	if err := os.WriteFile(tempPrefFile, encoded, 0600); err != nil {
		t.Fatalf("failed to write temp pref file: %v", err)
	}

	// 1. Test profile setting applied when no CLI flag is set
	utils.GlobalFlags.ConfigLicensePolicyFile = ""
	initConfigurations()

	// Verify policy loaded from preferences.json is used
	if LicensePolicyConfig == nil {
		t.Fatalf("expected LicensePolicyConfig to be initialized")
	}

	// 2. Test explicit CLI flag overrides preferences.json
	utils.GlobalFlags.ConfigLicensePolicyFile = "test/license/license-policy-test.json"
	initConfigurations()

	// Clean up global flag and restore defaults
	utils.GlobalFlags.ConfigLicensePolicyFile = ""
	_ = os.Remove(tempPrefFile)
	initConfigurations()
}
