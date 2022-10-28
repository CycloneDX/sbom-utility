[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# sbom-utility

## IBM SBOM Requirements

Requirements for tests come from the IBM SBOM Working Group.  The group uses the following repository to develop its canonical documentation and track ongoing work and issues:

- https://github.ibm.com/Supply-Chain-Security/ibm-sbom

The goal of the tests is to assure that all documented requirements are enforceable by the validation command the `sbom-utility`.

All requirements appear as subsections under the heading  [IBM SBOM requirements](https://github.ibm.com/Supply-Chain-Security/ibm-sbom/blob/master/README.md#ibm-sbom-requirements) and are organized as follows:

- [IBM SBOM requirements](  https://github.ibm.com/Supply-Chain-Security/ibm-sbom/blob/master/README.md#ibm-sbom-requirements)
  - [NTIA minimum required data](https://github.ibm.com/Supply-Chain-Security/ibm-sbom/blob/master/README.md#ntia-minimum-required-data)
  - [IBM required and optional data](https://github.ibm.com/Supply-Chain-Security/ibm-sbom/blob/master/README.md#ibm-required-and-optional-data)

Specifically, most of the requirements have been mapped by the group to CycloneDX here:

- [IBM SBOM CycloneDX Schema requirements](https://github.ibm.com/Supply-Chain-Security/ibm-sbom/blob/master/ibm-sbom-schema-cdx-requirements.md)

However, JSON schema cannot currently encode all requirements which we group here under the term "compositional".

---

### IBM custom test groupings

- [IBM custom schema tests](#ibm-custom-schema-tests) - ensure the `sbom-utility` can validate "custom" schema requirements and consistently report errors
- [IBM custom composition tests](#ibm-custom-composition-tests) - ensure the `sbom-utility` can validate "custom" schema requirements and consistently report errors

#### IBM custom schema tests

| Property | Required | Constraint | Test name | Test input file |
| :-- | :-- | :-- | :-- | :-- |
| `specVersion` | Y | `"enum": ["1.3", "1.4"]` | TODO | |
| `version` | Y | `"minimum": 1, "maximum": 1` | TODO | |
| `serialNumber` | Y |  `"pattern": "^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"` | TODO | |
| `metadata` | Y | N/A| TODO| |
| `components` | N | `"minItems": 1`, `"uniqueItems": true` (default)| TODO | |
| `services` | N | `"minItems": 1`, `"uniqueItems": true` (default)| TODO | |
| `dependencies` | N | `"minItems": 1`, `"uniqueItems": true` (default)| TODO | |
| `compositions` | N | `"minItems": 1`, `"uniqueItems": true` (default)| TODO | |
| | | | |

#### IBM custom composition tests

| Property | Required | Constraint | Test name | Test input file |
| :-- | :-- | :-- | :-- | :-- |
| | | | |
