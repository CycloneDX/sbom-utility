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
	// SBOM
	TEST_CDX_1_2_EXAMPLE_SBOM_CERN_LHC_VDM_EDITOR    = "examples/cyclonedx/SBOM/cern-lhc-vdm-editor-e564943/bom.json"
	TEST_CDX_1_2_EXAMPLE_SBOM_DROP_WIZARD_V1_3_15    = "examples/cyclonedx/SBOM/dropwizard-1.3.15/bom.json"
	TEST_CDX_1_2_EXAMPLE_SBOM_NPM_JUICE_SHOP_V11_1_2 = "examples/cyclonedx/SBOM/juice-shop-11.1.2/bom.json"
	TEST_CDX_1_2_EXAMPLE_SBOM_KEYCLOAK_V10_0_2       = "examples/cyclonedx/SBOM/keycloak-10.0.2/bom.json"
	TEST_CDX_1_3_EXAMPLE_SBOM_LARAVEL_V7_12_0        = "examples/cyclonedx/SBOM/laravel-7.12.0/bom.1.3.json"
	TEST_CDX_1_4_EXAMPLE_SBOM_LARAVEL_V7_12_0        = "examples/cyclonedx/SBOM/laravel-7.12.0/bom.1.4.json"
	TEST_CDX_1_2_EXAMPLE_SBOM_PROTON_BRIDGE_V1_6_3   = "examples/cyclonedx/SBOM/proton-bridge/proton-bridge-v1.6.3.bom.json"
	TEST_CDX_1_2_EXAMPLE_SBOM_PROTON_BRIDGE_V1_8_0   = "examples/cyclonedx/SBOM/proton-bridge/proton-bridge-v1.8.0.bom.json"
	TEST_CDX_1_2_EXAMPLE_SBOM_PROTON_MAIL_WEB_CLIENT = "examples/cyclonedx/SBOM/protonmail-webclient-v4-0912dff/bom.json"
	// SaaSBOM
	TEST_CDX_1_4_EXAMPLE_SAASBOM_APIGW_MS_DATASTORES = "examples/cyclonedx/SaaSBOM/apigateway-microservices-datastores/bom.json"
	// HBOM
	TEST_CDX_1_4_EXAMPLE_HBOM_PCI_SATA_ADAPTER_BOARD = "examples/cyclonedx/HBOM/PCIe-SATA-adapter-board/bom.json"
	// OBOM
	TEST_CDX_1_4_EXAMPLE_SBOM_KEYCLOAK_DECOUPLED  = "examples/cyclonedx/OBOM/Example-1-Decoupled/bom.json"
	TEST_CDX_1_4_EXAMPLE_OBOM_KEYCLOAK_DECOUPLED  = "examples/cyclonedx/OBOM/Example-1-Decoupled/obom.json"
	TEST_CDX_1_4_EXAMPLE_OBOM_KEYCLOAK_STANDALONE = "examples/cyclonedx/OBOM/Example-1-Standalone/bom.json"
	//VEX
	TEST_CDX_1_4_EXAMPLE_VEX_EXAMPLE_APP_BOM                     = "examples/cyclonedx/VEX/bom.json"
	TEST_CDX_1_4_EXAMPLE_VEX_EXAMPLE_APP_VEX                     = "examples/cyclonedx/VEX/vex.json"
	TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_1_AFFECTED            = "examples/cyclonedx/VEX/CISA-Use-Cases/Case-1/vex-affected.json"
	TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_1_FIXED               = "examples/cyclonedx/VEX/CISA-Use-Cases/Case-1/vex-fixed.json"
	TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_1_NOT_AFFECTED        = "examples/cyclonedx/VEX/CISA-Use-Cases/Case-1/vex-not_affected.json"
	TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_1_UNDER_INVESTIGATION = "examples/cyclonedx/VEX/CISA-Use-Cases/Case-1/vex-under_investigation.json"
	TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_2                     = "examples/cyclonedx/VEX/CISA-Use-Cases/Case-2/vex.json"
	TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_3                     = "examples/cyclonedx/VEX/CISA-Use-Cases/Case-3/vex.json"
	TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_4                     = "examples/cyclonedx/VEX/CISA-Use-Cases/Case-4/vex.json"
	TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_5                     = "examples/cyclonedx/VEX/CISA-Use-Cases/Case-4/vex.json"
	TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_6                     = "examples/cyclonedx/VEX/CISA-Use-Cases/Case-5/vex.json"
	TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_7                     = "examples/cyclonedx/VEX/CISA-Use-Cases/Case-7/vex.json"
	TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_7_1                   = "examples/cyclonedx/VEX/CISA-Use-Cases/Case-7/bom-1.json"
	TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_7_2                   = "examples/cyclonedx/VEX/CISA-Use-Cases/Case-7/bom-2.json"
	TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_8                     = "examples/cyclonedx/VEX/CISA-Use-Cases/Case-8/vex.json"
	TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_8_1                   = "examples/cyclonedx/VEX/CISA-Use-Cases/Case-8/bom-1.json"
	TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_8_2                   = "examples/cyclonedx/VEX/CISA-Use-Cases/Case-8/bom-2.json"
)

// CycloneDX - Examples
func TestValidateCdx12ExampleSBOMCernLhcVdmEditor(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_2_EXAMPLE_SBOM_CERN_LHC_VDM_EDITOR)
	innerValidateTest(t, *vti)
}

func TestValidateCdx12ExampleSBOMDropwizard(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_2_EXAMPLE_SBOM_DROP_WIZARD_V1_3_15)
	innerValidateTest(t, *vti)
}
func TestValidateCdx12ExampleSBOMNpmJuiceShop(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_2_EXAMPLE_SBOM_NPM_JUICE_SHOP_V11_1_2)
	innerValidateTest(t, *vti)
}

func TestValidateCdx12ExampleSBOMKeycloak(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_2_EXAMPLE_SBOM_KEYCLOAK_V10_0_2)
	innerValidateTest(t, *vti)
}

func TestValidateCdx13ExampleSBOMLaravel(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_3_EXAMPLE_SBOM_LARAVEL_V7_12_0)
	innerValidateTest(t, *vti)
}

func TestValidateCdx14ExampleSBOMLaravel(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_SBOM_LARAVEL_V7_12_0)
	innerValidateTest(t, *vti)
}

func TestValidateCdx12ExampleSaaSBOMProtonBridgeV163(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_2_EXAMPLE_SBOM_PROTON_BRIDGE_V1_6_3)
	innerValidateTest(t, *vti)
}

func TestValidateCdx12ExampleSaaSBOMProtonBridgeV180(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_2_EXAMPLE_SBOM_PROTON_BRIDGE_V1_8_0)
	innerValidateTest(t, *vti)
}

func TestValidateCdx12ExampleSaaSBOMProtonMailWebClient(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_2_EXAMPLE_SBOM_PROTON_MAIL_WEB_CLIENT)
	innerValidateTest(t, *vti)
}

func TestValidateCdx14ExampleSaaSBOMApiGatewayDatastores(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_SAASBOM_APIGW_MS_DATASTORES)
	innerValidateTest(t, *vti)
}

func TestValidateCdx14ExampleHBOMApiGatewayDatastores(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_HBOM_PCI_SATA_ADAPTER_BOARD)
	innerValidateTest(t, *vti)
}

func TestValidateCdx14ExampleOBOMKeycloakDecoupled(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_SBOM_KEYCLOAK_DECOUPLED)
	innerValidateTest(t, *vti)

	vti.InputFile = TEST_CDX_1_4_EXAMPLE_OBOM_KEYCLOAK_DECOUPLED
	innerValidateTest(t, *vti)
}

func TestValidateCdx14ExampleOBOMKeycloakStandalone(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_OBOM_KEYCLOAK_STANDALONE)
	innerValidateTest(t, *vti)

	vti.InputFile = TEST_CDX_1_4_EXAMPLE_OBOM_KEYCLOAK_DECOUPLED
	innerValidateTest(t, *vti)
}

// VEX
func TestValidateCdxExampleVEXExampleAppBOM(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_VEX_EXAMPLE_APP_BOM)
	innerValidateTest(t, *vti)
}

func TestValidateCdxExampleVEXExampleAppVEX(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_VEX_EXAMPLE_APP_VEX)
	innerValidateTest(t, *vti)
}

func TestValidateCdxExampleVEX_CISAUseCase1Affected(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_1_AFFECTED)
	innerValidateTest(t, *vti)
}
func TestValidateCdxExampleVEX_CISAUseCase1Fixed(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_1_FIXED)
	innerValidateTest(t, *vti)
}

func TestValidateCdxExampleVEX_CISAUseCase1NotAffected(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_1_NOT_AFFECTED)
	innerValidateTest(t, *vti)
}

func TestValidateCdxExampleVEX_CISAUseCase1UnderInvestigation(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_1_UNDER_INVESTIGATION)
	innerValidateTest(t, *vti)
}

func TestValidateCdxExampleVEX_CISAUseCase2(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_2)
	innerValidateTest(t, *vti)
}

func TestValidateCdxExampleVEX_CISAUseCase3(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_3)
	innerValidateTest(t, *vti)
}

func TestValidateCdxExampleVEX_CISAUseCase4(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_4)
	innerValidateTest(t, *vti)
}

func TestValidateCdxExampleVEX_CISAUseCase5(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_5)
	innerValidateTest(t, *vti)
}

func TestValidateCdxExampleVEX_CISAUseCase6(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_6)
	innerValidateTest(t, *vti)
}

func TestValidateCdxExampleVEX_CISAUseCase7(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_7)
	innerValidateTest(t, *vti)
}

func TestValidateCdxExampleVEX_CISAUseCase7_1(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_7_1)
	innerValidateTest(t, *vti)
}

func TestValidateCdxExampleVEX_CISAUseCase7_2(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_7_2)
	innerValidateTest(t, *vti)
}

func TestValidateCdxExampleVEX_CISAUseCase8(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_8)
	innerValidateTest(t, *vti)
}

func TestValidateCdxExampleVEX_CISAUseCase8_1(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_8_1)
	innerValidateTest(t, *vti)
}

func TestValidateCdxExampleVEX_CISAUseCase8_2(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_8_2)
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

func TestValidateCdxExampleCdx14UseCaseAssembly(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_ASSEMBLY)
	innerValidateTest(t, *vti)
}

func TestValidateCdxExampleCdx14UseCaseAuthenticityJsf(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_AUTHENTICITY_JSF)
	innerValidateTest(t, *vti)
}

func TestValidateCdxExampleCdx14UseCaseComponentKnownVulnerabilities(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_COMP_KNOWN_VULN)
	innerValidateTest(t, *vti)
}

func TestValidateCdxExampleCdx14UseCaseCompositionAndCompleteness(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_COMPOSITION_COMPLETENESS)
	innerValidateTest(t, *vti)
}

func TestValidateCdxExampleCdx14UseCaseDependencyGraph(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_DEP_GRAPH)
	innerValidateTest(t, *vti)
}

func TestValidateCdxExampleCdx14UseCaseExternalReferences(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_EXT_REFS)
	innerValidateTest(t, *vti)
}

func TestValidateCdxExampleCdx14UseCaseIntegrityVerification(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_INTEGRITY_VERIFICATION)
	innerValidateTest(t, *vti)
}

func TestValidateCdxExampleCdx14UseCaseInventory(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_INVENTORY)
	innerValidateTest(t, *vti)
}

func TestValidateCdxExampleCdx14UseCaseLicenseCompliance(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_LICENSE_COMPLIANCE)
	innerValidateTest(t, *vti)
}

func TestValidateCdxExampleCdx14UseCaseOpenChainConformance(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_OPENCHAIN_CONFORMANCE)
	innerValidateTest(t, *vti)
}

func TestValidateCdxExampleCdx14UseCasePackageEvaluation(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_PKG_EVALUATION)
	innerValidateTest(t, *vti)
}

func TestValidateCdxExampleCdx14UseCasePackagingDistribution(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_PKG_DIST)
	innerValidateTest(t, *vti)
}

func TestValidateCdxExampleCdx14UseCasePedigree(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_PEDIGREE)
	innerValidateTest(t, *vti)
}

func TestValidateCdxExampleCdx14UseCaseProvenance(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_PROVENANCE)
	innerValidateTest(t, *vti)
}

func TestValidateCdxExampleCdx14UseCaseSecurityAdvisories(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_SEC_ADVISORIES)
	innerValidateTest(t, *vti)
}

func TestValidateCdxExampleCdx14UseCaseServiceDefinition(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_SVC_DEFN)
	innerValidateTest(t, *vti)
}

func TestValidateCdxExampleCdx14UseCaseVulnerabilityExploitation(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_VULN_EXPLOITATION)
	innerValidateTest(t, *vti)
}

func TestValidateCdxExampleCdx14UseCaseVulnerabilityRemediation(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_VULN_REMEDIATION)
	innerValidateTest(t, *vti)
}
