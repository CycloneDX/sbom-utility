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
	"testing"
)

const (
	// -----------------------------------------------------
	// CycloneDX - Examples
	// -----------------------------------------------------
	// Note: these following examples are published by the CDX community here:
	// https://github.com/CycloneDX/bom-examples
	TEST_CDX_1_2_EXAMPLE_BOM_NPM_JUICE_SHOP          = "examples/cyclonedx/BOM/juice-shop-11.1.2/bom.json"
	TEST_CDX_1_3_EXAMPLE_BOM_LARAVEL                 = "examples/cyclonedx/BOM/laravel-7.12.0/bom.1.3.json"
	TEST_CDX_1_4_EXAMPLE_SAASBOM_APIGW_MS_DATASTORES = "examples/cyclonedx/SaaSBOM/apigateway-microservices-datastores/bom.json"

	// -----------------------------------------------------
	// CycloneDX - Use cases
	// -----------------------------------------------------
	// Note: all current CDX use cases currently reference v1.4 schema
	// Note: the following use cases are published by the CDX community here:
	// https://cyclonedx.org/use-cases/
	// These source for these use cases are found here:
	// https://github.com/CycloneDX/cyclonedx.org/tree/master/theme/_includes/examples
	TEST_EXAMPLE_CDX_1_4_USE_CASE_ASSEMBLY                 = "examples/cyclonedx/usecases/cdx-use-case-assembly.json"
	TEST_EXAMPLE_CDX_1_4_USE_CASE_AUTHENTICITY_JSF         = "examples/cyclonedx/usecases/cdx-use-case-authenticity-jsf.json"
	TEST_EXAMPLE_CDX_1_4_USE_CASE_COMP_KNOWN_VULN          = "examples/cyclonedx/usecases/cdx-use-case-component-known-vulnerabilities.json"
	TEST_EXAMPLE_CDX_1_4_USE_CASE_COMPOSITION_COMPLETENESS = "examples/cyclonedx/usecases/cdx-use-case-composition-and-completeness.json"
	TEST_EXAMPLE_CDX_1_4_USE_CASE_DEP_GRAPH                = "examples/cyclonedx/usecases/cdx-use-case-dependency-graph.json"
	TEST_EXAMPLE_CDX_1_4_USE_CASE_EXT_REFS                 = "examples/cyclonedx/usecases/cdx-use-case-external-references.json"
	TEST_EXAMPLE_CDX_1_4_USE_CASE_INTEGRITY_VERIFICATION   = "examples/cyclonedx/usecases/cdx-use-case-integrity-verification.json"
	TEST_EXAMPLE_CDX_1_4_USE_CASE_INVENTORY                = "examples/cyclonedx/usecases/cdx-use-case-inventory.json"
	TEST_EXAMPLE_CDX_1_4_USE_CASE_LICENSE_COMPLIANCE       = "examples/cyclonedx/usecases/cdx-use-case-license-compliance.json"
	TEST_EXAMPLE_CDX_1_4_USE_CASE_OPENCHAIN_CONFORMANCE    = "examples/cyclonedx/usecases/cdx-use-case-openchain-conformance.json"
	TEST_EXAMPLE_CDX_1_4_USE_CASE_PKG_EVALUATION           = "examples/cyclonedx/usecases/cdx-use-case-package-evaluation.json"
	TEST_EXAMPLE_CDX_1_4_USE_CASE_PKG_DIST                 = "examples/cyclonedx/usecases/cdx-use-case-packaging-and-distribution.json"
	TEST_EXAMPLE_CDX_1_4_USE_CASE_PEDIGREE                 = "examples/cyclonedx/usecases/cdx-use-case-pedigree.json"
	TEST_EXAMPLE_CDX_1_4_USE_CASE_PROVENANCE               = "examples/cyclonedx/usecases/cdx-use-case-provenance.json"
	TEST_EXAMPLE_CDX_1_4_USE_CASE_SEC_ADVISORIES           = "examples/cyclonedx/usecases/cdx-use-case-security-advisories.json"
	TEST_EXAMPLE_CDX_1_4_USE_CASE_SVC_DEFN                 = "examples/cyclonedx/usecases/cdx-use-case-service-defn.json"
	TEST_EXAMPLE_CDX_1_4_USE_CASE_VULN_EXPLOITATION        = "examples/cyclonedx/usecases/cdx-use-case-vulnerability-exploitability.json"
	TEST_EXAMPLE_CDX_1_4_USE_CASE_VULN_REMEDIATION         = "examples/cyclonedx/usecases/cdx-use-case-vulnerability-remediation.json"

	// TODO - turn these into tool independent test files
	//TEST_CRA_ALPINE            = "test/cyclonedx/samples/cra/fvt/data/alpine"
)

func TestValidateExampleCdx14UseCaseAssembly(t *testing.T) {
	innerValidateError(t, TEST_EXAMPLE_CDX_1_4_USE_CASE_ASSEMBLY, SCHEMA_VARIANT_NONE, FORMAT_TEXT, nil)
}

func TestValidateExampleCdx14UseCaseAuthenticityJsf(t *testing.T) {
	innerValidateError(t, TEST_EXAMPLE_CDX_1_4_USE_CASE_AUTHENTICITY_JSF, SCHEMA_VARIANT_NONE, FORMAT_TEXT, nil)
}

func TestValidateExampleCdx14UseCaseComponentKnownVulnerabilities(t *testing.T) {
	innerValidateError(t, TEST_EXAMPLE_CDX_1_4_USE_CASE_COMP_KNOWN_VULN, SCHEMA_VARIANT_NONE, FORMAT_TEXT, nil)
}

func TestValidateExampleCdx14UseCaseCompositionAndCompleteness(t *testing.T) {
	innerValidateError(t, TEST_EXAMPLE_CDX_1_4_USE_CASE_COMPOSITION_COMPLETENESS, SCHEMA_VARIANT_NONE, FORMAT_TEXT, nil)
}

func TestValidateExampleCdx14UseCaseDependencyGraph(t *testing.T) {
	innerValidateError(t, TEST_EXAMPLE_CDX_1_4_USE_CASE_DEP_GRAPH, SCHEMA_VARIANT_NONE, FORMAT_TEXT, nil)
}

func TestValidateExampleCdx14UseCaseExternalReferences(t *testing.T) {
	innerValidateError(t, TEST_EXAMPLE_CDX_1_4_USE_CASE_EXT_REFS, SCHEMA_VARIANT_NONE, FORMAT_TEXT, nil)
}

func TestValidateExampleCdx14UseCaseIntegrityVerification(t *testing.T) {
	innerValidateError(t, TEST_EXAMPLE_CDX_1_4_USE_CASE_INTEGRITY_VERIFICATION, SCHEMA_VARIANT_NONE, FORMAT_TEXT, nil)
}

func TestValidateExampleCdx14UseCaseInventory(t *testing.T) {
	innerValidateError(t, TEST_EXAMPLE_CDX_1_4_USE_CASE_INVENTORY, SCHEMA_VARIANT_NONE, FORMAT_TEXT, nil)
}

func TestValidateExampleCdx14UseCaseLicenseCompliance(t *testing.T) {
	innerValidateError(t, TEST_EXAMPLE_CDX_1_4_USE_CASE_LICENSE_COMPLIANCE, SCHEMA_VARIANT_NONE, FORMAT_TEXT, nil)
}

func TestValidateExampleCdx14UseCaseOpenChainConformance(t *testing.T) {
	innerValidateError(t, TEST_EXAMPLE_CDX_1_4_USE_CASE_OPENCHAIN_CONFORMANCE, SCHEMA_VARIANT_NONE, FORMAT_TEXT, nil)
}

func TestValidateExampleCdx14UseCasePackageEvaluation(t *testing.T) {
	innerValidateError(t, TEST_EXAMPLE_CDX_1_4_USE_CASE_PKG_EVALUATION, SCHEMA_VARIANT_NONE, FORMAT_TEXT, nil)
}

func TestValidateExampleCdx14UseCasePackagingDistribution(t *testing.T) {
	innerValidateError(t, TEST_EXAMPLE_CDX_1_4_USE_CASE_PKG_DIST, SCHEMA_VARIANT_NONE, FORMAT_TEXT, nil)
}

func TestValidateExampleCdx14UseCasePedigree(t *testing.T) {
	innerValidateError(t, TEST_EXAMPLE_CDX_1_4_USE_CASE_PEDIGREE, SCHEMA_VARIANT_NONE, FORMAT_TEXT, nil)
}

func TestValidateExampleCdx14UseCaseProvenance(t *testing.T) {
	innerValidateError(t, TEST_EXAMPLE_CDX_1_4_USE_CASE_PROVENANCE, SCHEMA_VARIANT_NONE, FORMAT_TEXT, nil)
}

func TestValidateExampleCdx14UseCaseSecurityAdvisories(t *testing.T) {
	innerValidateError(t, TEST_EXAMPLE_CDX_1_4_USE_CASE_SEC_ADVISORIES, SCHEMA_VARIANT_NONE, FORMAT_TEXT, nil)
}

func TestValidateExampleCdx14UseCaseServiceDefinition(t *testing.T) {
	innerValidateError(t, TEST_EXAMPLE_CDX_1_4_USE_CASE_SVC_DEFN, SCHEMA_VARIANT_NONE, FORMAT_TEXT, nil)
}

func TestValidateExampleCdx14UseCaseVulnerabilityExploitation(t *testing.T) {
	innerValidateError(t, TEST_EXAMPLE_CDX_1_4_USE_CASE_VULN_EXPLOITATION, SCHEMA_VARIANT_NONE, FORMAT_TEXT, nil)
}

func TestValidateExampleCdx14UseCaseVulnerabilityRemediation(t *testing.T) {
	innerValidateError(t, TEST_EXAMPLE_CDX_1_4_USE_CASE_VULN_REMEDIATION, SCHEMA_VARIANT_NONE, FORMAT_TEXT, nil)
}

// CycloneDX - Examples
func TestValidateExampleBomCdx12NpmJuiceShop(t *testing.T) {
	innerValidateError(t, TEST_CDX_1_2_EXAMPLE_BOM_NPM_JUICE_SHOP, SCHEMA_VARIANT_NONE, FORMAT_TEXT, nil)
}

func TestValidateExampleBomCdx13Laravel(t *testing.T) {
	innerValidateError(t, TEST_CDX_1_3_EXAMPLE_BOM_LARAVEL, SCHEMA_VARIANT_NONE, FORMAT_TEXT, nil)
}

func TestValidateExampleSaaSBomCdx14ApiGatewayDatastores(t *testing.T) {
	innerValidateError(t, TEST_CDX_1_4_EXAMPLE_SAASBOM_APIGW_MS_DATASTORES, SCHEMA_VARIANT_NONE, FORMAT_TEXT, nil)
}
