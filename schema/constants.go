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

package schema

// Supported schemas will be identified (or "keyed") uniquely using values:
// - Format ID (e.g., "SPDXRef-DOCUMENT", "CycloneDX") - identifies the format/standard
// - Schema version (e.g., "SPDX-2.2", "" )
// ASSUMPTIONS:
// - Since we see that both SPDX and CycloneDX both support "semver" of their specification versions
// BUT, they only provide the "MAJOR.MINOR" components of "semver" we will use the
// "latest" ".PATCH" version of the JSON schema to test against
// NOTE: If any of these 3 components are not found in an SBOM then the schema is not deterministic.
// TODO:  support "override" or "supplemental" (defaults) to be provided on the command line.
// TODO: Allow for discrete "semver" for a schema to be provided as an override
// that includes full "MAJOR.MINOR.PATCH" granularity

// Format ID (key component)
// UNUSED, TODO Use these values to verify remotely loaded schema files
const (
	ID_SPDX      = "SPDXRef-DOCUMENT"
	ID_CYCLONEDX = "CycloneDX"
)

// Document property keys
// JSON document property keys to lookup values in their respective SBOM formats
// UNUSED, TODO Use these values to verify remotely loaded schema files
const (
	// SPDX
	PROPKEY_ID_SPDX      = "SPDXID"
	PROPKEY_VERSION_SPDX = "spdxVersion"
	// CycloneDX
	PROPKEY_ID_CYCLONEDX      = "bomFormat"
	PROPKEY_VERSION_CYCLONEDX = "specVersion"
)
