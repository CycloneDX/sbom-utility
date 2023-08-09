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

// -----------------------------------------------------
// CycloneDX - Examples
// -----------------------------------------------------
// Note: these following examples are published by the CDX community here:
// https://github.com/CycloneDX/bom-examples
const (
	TEST_CDX_1_2_EXAMPLE_SBOM_CERN_LHC_VDM_EDITOR    = "examples/cyclonedx/SBOM/cern-lhc-vdm-editor-e564943/bom.json"
	TEST_CDX_1_2_EXAMPLE_SBOM_DROP_WIZARD_V1_3_15    = "examples/cyclonedx/SBOM/dropwizard-1.3.15/bom.json"
	TEST_CDX_1_2_EXAMPLE_SBOM_NPM_JUICE_SHOP_V11_1_2 = "examples/cyclonedx/SBOM/juice-shop-11.1.2/bom.json"
	TEST_CDX_1_2_EXAMPLE_SBOM_KEYCLOAK_V10_0_2       = "examples/cyclonedx/SBOM/keycloak-10.0.2/bom.json"
	TEST_CDX_1_3_EXAMPLE_SBOM_LARAVEL_V7_12_0        = "examples/cyclonedx/SBOM/laravel-7.12.0/bom.1.3.json"
	TEST_CDX_1_4_EXAMPLE_SBOM_LARAVEL_V7_12_0        = "examples/cyclonedx/SBOM/laravel-7.12.0/bom.1.4.json"
	TEST_CDX_1_2_EXAMPLE_SBOM_PROTON_BRIDGE_V1_6_3   = "examples/cyclonedx/SBOM/proton-bridge/proton-bridge-v1.6.3.bom.json"
	TEST_CDX_1_2_EXAMPLE_SBOM_PROTON_BRIDGE_V1_8_0   = "examples/cyclonedx/SBOM/proton-bridge/proton-bridge-v1.8.0.bom.json"
	TEST_CDX_1_2_EXAMPLE_SBOM_PROTON_MAIL_WEB_CLIENT = "examples/cyclonedx/SBOM/protonmail-webclient-v4-0912dff/bom.json"
	TEST_CDX_1_4_EXAMPLE_SAASBOM_APIGW_MS_DATASTORES = "examples/cyclonedx/SaaSBOM/apigateway-microservices-datastores/bom.json"
	TEST_CDX_1_4_EXAMPLE_HBOM_PCI_SATA_ADAPTER_BOARD = "examples/cyclonedx/HBOM/PCIe-SATA-adapter-board/bom.json"
	TEST_CDX_1_4_EXAMPLE_SBOM_KEYCLOAK_DECOUPLED     = "examples/cyclonedx/OBOM/Example-1-Decoupled/bom.json"
	TEST_CDX_1_4_EXAMPLE_OBOM_KEYCLOAK_DECOUPLED     = "examples/cyclonedx/OBOM/Example-1-Decoupled/obom.json"
	TEST_CDX_1_4_EXAMPLE_OBOM_KEYCLOAK_STANDALONE    = "examples/cyclonedx/OBOM/Example-1-Standalone/bom.json"
)

// CycloneDX - Examples
func TestValidateExampleSBOMCdx12CERN_LHC_VDMEditor(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_2_EXAMPLE_SBOM_CERN_LHC_VDM_EDITOR)
	innerValidateTest(t, *vti)
}

func TestValidateExampleSBOMCdx12Dropwizard(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_2_EXAMPLE_SBOM_DROP_WIZARD_V1_3_15)
	innerValidateTest(t, *vti)
}
func TestValidateExampleSBOMCdx12NpmJuiceShop(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_2_EXAMPLE_SBOM_NPM_JUICE_SHOP_V11_1_2)
	innerValidateTest(t, *vti)
}

func TestValidateExampleSBOMCdx12Keycloak(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_2_EXAMPLE_SBOM_KEYCLOAK_V10_0_2)
	innerValidateTest(t, *vti)
}

func TestValidateExampleSBOMCdx13Laravel(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_3_EXAMPLE_SBOM_LARAVEL_V7_12_0)
	innerValidateTest(t, *vti)
}

func TestValidateExampleSBOMCdx14Laravel(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_SBOM_LARAVEL_V7_12_0)
	innerValidateTest(t, *vti)
}

func TestValidateExampleSaaSBOMCdx12ProtonBridgeV163(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_2_EXAMPLE_SBOM_PROTON_BRIDGE_V1_6_3)
	innerValidateTest(t, *vti)
}

func TestValidateExampleSaaSBOMCdx12ProtonBridgeV180(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_2_EXAMPLE_SBOM_PROTON_BRIDGE_V1_8_0)
	innerValidateTest(t, *vti)
}

func TestValidateExampleSaaSBOMCdx12ProtonMailWebClient(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_2_EXAMPLE_SBOM_PROTON_MAIL_WEB_CLIENT)
	innerValidateTest(t, *vti)
}

func TestValidateExampleSaaSBOMCdx14ApiGatewayDatastores(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_SAASBOM_APIGW_MS_DATASTORES)
	innerValidateTest(t, *vti)
}

func TestValidateExampleHBOMCdx14ApiGatewayDatastores(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_HBOM_PCI_SATA_ADAPTER_BOARD)
	innerValidateTest(t, *vti)
}

func TestValidateExampleOBOMCdx14KeycloakDecoupled(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_SBOM_KEYCLOAK_DECOUPLED)
	innerValidateTest(t, *vti)

	vti.InputFile = TEST_CDX_1_4_EXAMPLE_OBOM_KEYCLOAK_DECOUPLED
	innerValidateTest(t, *vti)
}

func TestValidateExampleOBOMCdx14KeycloakStandalone(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_OBOM_KEYCLOAK_STANDALONE)
	innerValidateTest(t, *vti)

	vti.InputFile = TEST_CDX_1_4_EXAMPLE_OBOM_KEYCLOAK_DECOUPLED
	innerValidateTest(t, *vti)
}

// -----------------------------------------------------
// CycloneDX - Use cases
// -----------------------------------------------------
// Note: all current CDX use cases currently reference v1.4 schema
// Note: the following use cases are published by the CDX community here:
// https://cyclonedx.org/use-cases/
// These source for these use cases are found here:
// https://github.com/CycloneDX/cyclonedx.org/tree/master/theme/_includes/examples
const (
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
)

func TestValidateExampleCdx14UseCaseAssembly(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_ASSEMBLY)
	innerValidateTest(t, *vti)
}

func TestValidateExampleCdx14UseCaseAuthenticityJsf(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_AUTHENTICITY_JSF)
	innerValidateTest(t, *vti)
}

func TestValidateExampleCdx14UseCaseComponentKnownVulnerabilities(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_COMP_KNOWN_VULN)
	innerValidateTest(t, *vti)
}

func TestValidateExampleCdx14UseCaseCompositionAndCompleteness(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_COMPOSITION_COMPLETENESS)
	innerValidateTest(t, *vti)
}

func TestValidateExampleCdx14UseCaseDependencyGraph(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_DEP_GRAPH)
	innerValidateTest(t, *vti)
}

func TestValidateExampleCdx14UseCaseExternalReferences(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_EXT_REFS)
	innerValidateTest(t, *vti)
}

func TestValidateExampleCdx14UseCaseIntegrityVerification(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_INTEGRITY_VERIFICATION)
	innerValidateTest(t, *vti)
}

func TestValidateExampleCdx14UseCaseInventory(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_INVENTORY)
	innerValidateTest(t, *vti)
}

func TestValidateExampleCdx14UseCaseLicenseCompliance(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_LICENSE_COMPLIANCE)
	innerValidateTest(t, *vti)
}

func TestValidateExampleCdx14UseCaseOpenChainConformance(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_OPENCHAIN_CONFORMANCE)
	innerValidateTest(t, *vti)
}

func TestValidateExampleCdx14UseCasePackageEvaluation(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_PKG_EVALUATION)
	innerValidateTest(t, *vti)
}

func TestValidateExampleCdx14UseCasePackagingDistribution(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_PKG_DIST)
	innerValidateTest(t, *vti)
}

func TestValidateExampleCdx14UseCasePedigree(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_PEDIGREE)
	innerValidateTest(t, *vti)
}

func TestValidateExampleCdx14UseCaseProvenance(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_PROVENANCE)
	innerValidateTest(t, *vti)
}

func TestValidateExampleCdx14UseCaseSecurityAdvisories(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_SEC_ADVISORIES)
	innerValidateTest(t, *vti)
}

func TestValidateExampleCdx14UseCaseServiceDefinition(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_SVC_DEFN)
	innerValidateTest(t, *vti)
}

func TestValidateExampleCdx14UseCaseVulnerabilityExploitation(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_VULN_EXPLOITATION)
	innerValidateTest(t, *vti)
}

func TestValidateExampleCdx14UseCaseVulnerabilityRemediation(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_VULN_REMEDIATION)
	innerValidateTest(t, *vti)
}
