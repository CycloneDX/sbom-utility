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
// NOTE: If any of these 3 components are not found in an SBOM then the schema is
// not deterministic.
// TODO:  support "override" or "supplemental" (defaults) to be provided on
// the command line.
// TODO: Allow for discrete "semver" for a scheam to be provided as an override
// that includes full "MAJOR.MINOR.PATCH" granularity

// Format ID (key component)
const (
	ID_SPDX      = "SPDXRef-DOCUMENT"
	ID_CYCLONEDX = "CycloneDX"
)

// Document property keys
// JSON document property keys to lookup values in their respective SBOM formats
const (
	// SPDX
	PROPKEY_ID_SPDX      = "SPDXID"
	PROPKEY_VERSION_SPDX = "spdxVersion"
	// CycloneDX
	PROPKEY_ID_CYCLONEDX      = "bomFormat"
	PROPKEY_VERSION_CYCLONEDX = "specVersion"
)

// Version (key component)
const (
	VERSION_SPDX_2_2      = "SPDX-2.2"
	VERSION_CYCLONEDX_1_3 = "1.3"
)

// TODO: Support remote schema retrieval as an optional program flag
// However, we want to default to local for performance where possible
// as well as plan for local, secure bundling of schema with this utility
// in CI build systems (towards improved security, isolated builds)
// NOTE: we have also found that standards orgs. freely move their schema files
// within SCM systems thereby being a cause for remote retrieval failures.
const (
	SCHEMA_SPDX_2_2_2_LOCAL            = "file://schema/spdx/2.2/spdx-schema.json"
	SCHEMA_SPDX_2_2_2_REMOTE           = "https://github.com/spdx/spdx-spec/blob/master/schemas/spdx-schema.json"
	SCHEMA_CYCLONEDX_1_3_LOCAL         = "file://schema/cyclonedx/1.3/bom-1.3.schema.json"
	SCHEMA_CYCLONEDX_1_3_REMOTE        = "https://github.com/CycloneDX/specification/blob/master/schema/bom-1.3.schema.json"
	SCHEMA_CYCLONEDX_1_3_STRICT_LOCAL  = "file://schema/cyclonedx/1.3/bom-1.3-strict.schema.json"
	SCHEMA_CYCLONEDX_1_3_STRICT_REMOTE = "https://github.com/CycloneDX/specification/blob/master/schema/bom-1.3-strict.schema.json"
)
