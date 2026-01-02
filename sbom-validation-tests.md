[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# sbom-utility

## SBOM validation tests

Validation tests are logically grouped by files as well as categories.

---

### validate_test.go

The tests in this section are all found in [`cmd/validate_test.go`](cmd/validate_test.go).

#### Input file tests

Assures the utility properly handles invalid values on the `--input` (or `-i`) flag.

| Test name | Description | Test input file | Expected results | Notes |
| :-- | :-- | :-- | :-- | :-- |
| TestValidateInvalidInputFileLoad | Test for invalid input file provided on the `-i` flag | TEST_INPUT_FILE_NON_EXISTENT | `fs.PathError`  |  |

---

#### JSON syntax error tests

Assures the utility properly handles different kinds of syntax errors in JSON documents (i.e., SBOMs) with the expected location (offset).

**Note** Syntax error tests SHOULD return error type `encoding/json.SyntaxError`

| Test name | Description | Syntax Error | Test input file |
| :-- | :-- | :-- | :-- |
|  TestValidateSyntaxErrorCdx13Test1 | Missing closing `}` bracket on `metadata` property  | "invalid character '{' after object key" | [test/cyclonedx/1.3/cdx-1-3-syntax-err-1.json](test/cyclonedx/1.3/cdx-1-3-syntax-err-1.json) |
| TestValidateSyntaxErrorCdx13Test2 | Missing `:` separating `"properties"` key from array value `[` | "invalid character '[' after object key" | [test/cyclonedx/1.3/cdx-1-3-syntax-err-2.json](test/cyclonedx/1.3/cdx-1-3-syntax-err-2.json) |

---

#### Custom schema tests

Test custom schema validation (i.e., schemas provided using the `--force` flag).

| Test name | Description | Schema file | Test input file | Expected results |
| :-- | :-- | :-- | :-- | :-- |
| TestValidateForceCustomSchemaCdx13 | Force validation against a "custom" schema with compatible format (CDX) and version (1.3) | TEST_SCHEMA_CDX_1_3_CUSTOM | TEST_CDX_1_3_MATURITY_BASE | *valid* |
| TestValidateForceCustomSchemaCdx14 | Force validation against a "custom" schema with compatible format (CDX) and version (1.4) | TEST_SCHEMA_CDX_1_4_CUSTOM | TEST_CDX_1_4_MATURITY_BASE | *valid* |
| TestValidateForceCustomSchemaCdxSchemaOlder | Force validation using schema with compatible format, but older version than the SBOM version | TEST_SCHEMA_CDX_1_3_CUSTOM | TEST_CDX_1_4_MATURITY_BASE | *valid* |

---

### validate_config_test.go

The tests in this section are all found in [`cmd/validate_config_test.go`](cmd/validate_test.go).

#### Configuration tests

These tests verify that errors related to the `config.json` file entries (e.g., lookup of undefined formats, versions or variants) are returned properly.

| Test name | Description | Expected results | Test input file | Notes |
| :-- | :-- | :-- | :-- | :-- |
| TestValidateConfigInvalidFormatKey | Error if SBOM "format" (key) undefined. |  `UnsupportedFormatError` | [test/config/test-base-invalid-format-key-foo.json](test/config/test-base-invalid-format-key-foo.json) | |
| TestValidateConfigInvalidVersion         | Error if SBOM schema "version" not found (invalid) for a defined format. |  `UnsupportedSchemaError` |  [test/cyclonedx/cdx-1-x-test-invalid-spec-version.json](test/cyclonedx/cdx-1-x-test-invalid-spec-version.json) | |
| TestValidateConfigInvalidVariant         | Error if SBOM schema "variant" not found (invalid) for a defined format and version. |  `UnsupportedSchemaError` | [test/cyclonedx/1.4/cdx-1-4-min-required.json](test/cyclonedx/1.4/cdx-1-4-min-required.json) | Reuse existing test file with valid format and version as `variant` value will not be found |
| TestValidateConfigCDXBomFormatInvalid    | CDX `bomFormat` key value is invalid. | `UnsupportedFormatError` | [test/config/test-cdx-bom-format-invalid.json](test/config/test-cdx-bom-format-invalid.json) | |
| TestValidateConfigCDXBomFormatMissing    | CDX `bomFormat` key is missing. | `UnsupportedFormatError` | [test/config/test-cdx-bom-format-missing.json](test/config/test-cdx-bom-format-missing.json) | |
| TestValidateConfigCDXSpecVersionMissing  | CDX `specVersion` key is missing. | `UnsupportedSchemaError` | [test/config/test-cdx-spec-version-missing.json](test/config/test-cdx-spec-version-missing.json) | |
| TestValidateConfigSPDXSpdxIdInvalid      | SPDX `SPDXID` key is invalid. | `UnsupportedFormatError` | [test/config/test-spdx-spdx-id-invalid.json](test/config/test-spdx-spdx-id-invalid.json) | |
| TestValidateConfigSPDXSpdxVersionInvalid | SPDX `spdxVersion` key is invalid. | `UnsupportedSchemaError` | [test/config/test-spdx-spdx-version-missing.json](test/config/test-spdx-spdx-version-missing.json) | |

---

#### CycloneDX Minimum Requirements tests

| Test name | Description | Expected results | Test input file | Notes |
| :-- | :-- | :-- | :-- | :-- |
| TestValidateCdx13MinRequiredBasic |  |  |  |  |
| TestValidateCdx14MinRequiredBasic |  |  |  |  |

---

#### CycloneDX Example tests

| Test name | Description | Expected results | Test input file | Notes |
| :-- | :-- | :-- | :-- | :-- |
| TestValidateExampleCdx14UseCaseAssembly |  |  |  |  |
| TestValidateExampleCdx14UseCaseAuthenticityJsf |  |  |  |  |
| TestValidateExampleCdx14UseCaseComponentKnownVulnerabilities |  |  |  |  |
| TestValidateExampleCdx14UseCaseCompositionAndCompleteness |  |  |  |  |
| TestValidateExampleCdx14UseCaseDependencyGraph |  |  |  |  |
| TestValidateExampleCdx14UseCaseExternalReferences |  |  |  |  |
| TestValidateExampleCdx14UseCaseIntegrityVerification |  |  |  |  |
| TestValidateExampleCdx14UseCaseInventory |  |  |  |  |
| TestValidateExampleCdx14UseCaseLicenseCompliance |  |  |  |  |
| TestValidateExampleCdx14UseCaseOpenChainConformance |  |  |  |  |
| TestValidateExampleCdx14UseCasePackageEvaluation |  |  |  |  |
| TestValidateExampleCdx14UseCasePackagingDistribution |  |  |  |  |
| TestValidateExampleCdx14UseCasePedigree |  |  |  |  |
| TestValidateExampleCdx14UseCaseProvenance |  |  |  |  |
| TestValidateExampleCdx14UseCaseSecurityAdvisories |  |  |  |  |
| TestValidateExampleCdx14UseCaseServiceDefinition |  |  |  |  |
| TestValidateExampleCdx14UseCaseVulnerabilityExploitation |  |  |  |  |
| TestValidateExampleCdx14UseCaseVulnerabilityRemediation |  |  |  |  |
| TestValidateExampleBomCdx12NpmJuiceShop |  |  |  |  |
| TestValidateExampleBomCdx13Laravel |  |  |  |  |
| TestValidateExampleSaaSBomCdx14ApiGatewayDatastores |  |  |  |  |
