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
	innerTestValidate(t, *vti)
}

func TestValidateCdx12ExampleSBOMDropwizard(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_2_EXAMPLE_SBOM_DROP_WIZARD_V1_3_15)
	innerTestValidate(t, *vti)
}
func TestValidateCdx12ExampleSBOMNpmJuiceShop(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_2_EXAMPLE_SBOM_NPM_JUICE_SHOP_V11_1_2)
	innerTestValidate(t, *vti)
}

func TestValidateCdx12ExampleSBOMKeycloak(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_2_EXAMPLE_SBOM_KEYCLOAK_V10_0_2)
	innerTestValidate(t, *vti)
}

func TestValidateCdx13ExampleSBOMLaravel(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_3_EXAMPLE_SBOM_LARAVEL_V7_12_0)
	innerTestValidate(t, *vti)
}

func TestValidateCdx14ExampleSBOMLaravel(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_SBOM_LARAVEL_V7_12_0)
	innerTestValidate(t, *vti)
}

func TestValidateCdx12ExampleSaaSBOMProtonBridgeV163(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_2_EXAMPLE_SBOM_PROTON_BRIDGE_V1_6_3)
	innerTestValidate(t, *vti)
}

func TestValidateCdx12ExampleSaaSBOMProtonBridgeV180(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_2_EXAMPLE_SBOM_PROTON_BRIDGE_V1_8_0)
	innerTestValidate(t, *vti)
}

func TestValidateCdx12ExampleSaaSBOMProtonMailWebClient(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_2_EXAMPLE_SBOM_PROTON_MAIL_WEB_CLIENT)
	innerTestValidate(t, *vti)
}

func TestValidateCdx14ExampleSaaSBOMApiGatewayDatastores(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_SAASBOM_APIGW_MS_DATASTORES)
	innerTestValidate(t, *vti)
}

func TestValidateCdx14ExampleHBOMApiGatewayDatastores(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_HBOM_PCI_SATA_ADAPTER_BOARD)
	innerTestValidate(t, *vti)
}

func TestValidateCdx14ExampleOBOMKeycloakDecoupled(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_SBOM_KEYCLOAK_DECOUPLED)
	innerTestValidate(t, *vti)

	vti.InputFile = TEST_CDX_1_4_EXAMPLE_OBOM_KEYCLOAK_DECOUPLED
	innerTestValidate(t, *vti)
}

func TestValidateCdx14ExampleOBOMKeycloakStandalone(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_OBOM_KEYCLOAK_STANDALONE)
	innerTestValidate(t, *vti)

	vti.InputFile = TEST_CDX_1_4_EXAMPLE_OBOM_KEYCLOAK_DECOUPLED
	innerTestValidate(t, *vti)
}

// VEX
func TestValidateCdx14ExampleVEXExampleAppBOM(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_VEX_EXAMPLE_APP_BOM)
	innerTestValidate(t, *vti)
}

func TestValidateCdx14ExampleVEXExampleAppVEX(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_VEX_EXAMPLE_APP_VEX)
	innerTestValidate(t, *vti)
}

func TestValidateCdx14ExampleVEX_CISAUseCase1Affected(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_1_AFFECTED)
	innerTestValidate(t, *vti)
}
func TestValidateCdx14ExampleVEX_CISAUseCase1Fixed(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_1_FIXED)
	innerTestValidate(t, *vti)
}

func TestValidateCdx14ExampleVEX_CISAUseCase1NotAffected(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_1_NOT_AFFECTED)
	innerTestValidate(t, *vti)
}

func TestValidateCdx14ExampleVEX_CISAUseCase1UnderInvestigation(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_1_UNDER_INVESTIGATION)
	innerTestValidate(t, *vti)
}

func TestValidateCdx14ExampleVEX_CISAUseCase2(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_2)
	innerTestValidate(t, *vti)
}

func TestValidateCdx14ExampleVEX_CISAUseCase3(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_3)
	innerTestValidate(t, *vti)
}

func TestValidateCdx14ExampleVEX_CISAUseCase4(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_4)
	innerTestValidate(t, *vti)
}

func TestValidateCdx14ExampleVEX_CISAUseCase5(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_5)
	innerTestValidate(t, *vti)
}

func TestValidateCdx14ExampleVEX_CISAUseCase6(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_6)
	innerTestValidate(t, *vti)
}

func TestValidateCdx14ExampleVEX_CISAUseCase7(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_7)
	innerTestValidate(t, *vti)
}

func TestValidateCdx14ExampleVEX_CISAUseCase7_1(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_7_1)
	innerTestValidate(t, *vti)
}

func TestValidateCdx14ExampleVEX_CISAUseCase7_2(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_7_2)
	innerTestValidate(t, *vti)
}

func TestValidateCdx14ExampleVEX_CISAUseCase8(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_8)
	innerTestValidate(t, *vti)
}

func TestValidateCdx14ExampleVEX_CISAUseCase8_1(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_8_1)
	innerTestValidate(t, *vti)
}

func TestValidateCdx14ExampleVEX_CISAUseCase8_2(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_CDX_1_4_EXAMPLE_VEX_CISA_USE_CASE_8_2)
	innerTestValidate(t, *vti)
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

func TestValidateCdx14ExampleUseCaseAssembly(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_ASSEMBLY)
	innerTestValidate(t, *vti)
}

func TestValidateCdx14ExampleUseCaseAuthenticityJsf(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_AUTHENTICITY_JSF)
	innerTestValidate(t, *vti)
}

func TestValidateCdx14ExampleUseCaseComponentKnownVulnerabilities(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_COMP_KNOWN_VULN)
	innerTestValidate(t, *vti)
}

func TestValidateCdx14ExampleUseCaseCompositionAndCompleteness(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_COMPOSITION_COMPLETENESS)
	innerTestValidate(t, *vti)
}

func TestValidateCdx14ExampleUseCaseDependencyGraph(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_DEP_GRAPH)
	innerTestValidate(t, *vti)
}

func TestValidateCdx14ExampleUseCaseExternalReferences(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_EXT_REFS)
	innerTestValidate(t, *vti)
}

func TestValidateCdx14ExampleUseCaseIntegrityVerification(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_INTEGRITY_VERIFICATION)
	innerTestValidate(t, *vti)
}

func TestValidateCdx14ExampleUseCaseInventory(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_INVENTORY)
	innerTestValidate(t, *vti)
}

func TestValidateCdx14ExampleUseCaseLicenseCompliance(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_LICENSE_COMPLIANCE)
	innerTestValidate(t, *vti)
}

func TestValidateCdx14ExampleUseCaseOpenChainConformance(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_OPENCHAIN_CONFORMANCE)
	innerTestValidate(t, *vti)
}

func TestValidateCdx14ExampleUseCasePackageEvaluation(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_PKG_EVALUATION)
	innerTestValidate(t, *vti)
}

func TestValidateCdx14ExampleUseCasePackagingDistribution(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_PKG_DIST)
	innerTestValidate(t, *vti)
}

func TestValidateCdx14ExampleUseCasePedigree(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_PEDIGREE)
	innerTestValidate(t, *vti)
}

func TestValidateCdx14ExampleUseCaseProvenance(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_PROVENANCE)
	innerTestValidate(t, *vti)
}

func TestValidateCdx14ExampleUseCaseSecurityAdvisories(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_SEC_ADVISORIES)
	innerTestValidate(t, *vti)
}

func TestValidateCdx14ExampleUseCaseServiceDefinition(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_SVC_DEFN)
	innerTestValidate(t, *vti)
}

func TestValidateCdx14ExampleUseCaseVulnerabilityExploitation(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_VULN_EXPLOITATION)
	innerTestValidate(t, *vti)
}

func TestValidateCdx14ExampleUseCaseVulnerabilityRemediation(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_EXAMPLE_CDX_1_4_USE_CASE_VULN_REMEDIATION)
	innerTestValidate(t, *vti)
}
