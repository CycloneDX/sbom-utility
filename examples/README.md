# SBOM examples

## CycloneDX examples

For convenience, examples are copied locally from:

- https://github.com/CycloneDX/sbom-examples

The are categorized by BOM type:

| Name/Version | JSON | Type | bom-ref | Description |
| :-- | :-- | :-- | :-- | :-- |
| juice-shop v11.1.2 | [cyclonedx/BOM/juice-shop-11.1.2/bom.json](cyclonedx/BOM/juice-shop-11.1.2/bom.json) | library | `pkg:npm/juice-shop@11.1.2`| "Probably the most modern and sophisticated insecure web application" |
| laravel v7.12.0 | [cyclonedx/BOM/laravel-7.12.0/bom.1.3.json](cyclonedx/BOM/laravel-7.12.0/bom.1.3.json) | application | `pkg:composer/cyclonedx/cyclonedx-php-composer-demo@dev-master` | "demo of cyclonedx/cyclonedx-php-composer with a pinned version of laravel/framework" |
| API Gateway microservices application | [cyclonedx/SaaSBOM/apigateway-microservices-datastores/bom.json](cyclonedx/SaaSBOM/apigateway-microservices-datastores/bom.json) | application | `acme-application` | An application composed of services which are represented in the BOM. |

## CycloneDX use cases

Canonical (CycloneDX v1.4, JSON format) use cases with sample code:

- https://cyclonedx.org/use-cases

| CDX Version | Use case | Test file (JSON) | Description |
| :-- | :-- | :-- | :-- |
| 1.4| [Inventory](https://cyclonedx.org/use-cases/#known-vulnerabilitiesServ) | [cyclonedx/usecases/cdx-use-case-inventory.json](cyclonedx/usecases/cdx-use-case-inventory.json) | Includes all supported component `type` values |
| 1.4 | [Known vulnerabilities](https://cyclonedx.org/use-cases/#known-vulnerabilities) | [cyclonedx/usecases/cdx-use-case-component-known-vulnerabilities.json](cyclonedx/usecases/cdx-use-case-component-known-vulnerabilities.json) | Includes all supported component `type` values |
| 1.4 | [Integrity verification](https://cyclonedx.org/use-cases/#integrity-verification) | [cyclonedx/usecases/cdx-use-case-integrity-verification.json](cyclonedx/usecases/cdx-use-case-integrity-verification.json) |  |
| 1.4 | [Authenticity](https://cyclonedx.org/use-cases/#authenticity) (JSF) | [cyclonedx/usecases/cdx-use-case-authenticity-jsf.json](cyclonedx/usecases/cdx-use-case-authenticity-jsf.json) |  |
| 1.4 | [Package evaluation](https://cyclonedx.org/use-cases/#package-evaluation) | [cyclonedx/usecases/cdx-use-case-package-evaluation.json](cyclonedx/usecases/cdx-use-case-package-evaluation.json) |  |
| 1.4 | [License compliance](https://cyclonedx.org/use-cases/#license-compliance) | [cyclonedx/usecases/cdx-use-case-license-compliance.json](cyclonedx/usecases/cdx-use-case-license-compliance.json) |  |
| 1.4 | [Assembly](https://cyclonedx.org/use-cases/#assembly) | [cyclonedx/usecases/cdx-use-case-assembly.json](cyclonedx/usecases/cdx-use-case-assembly.json) | |
| 1.4 | [Dependency graph](https://cyclonedx.org/use-cases/#dependency-graph) | [cyclonedx/usecases/cdx-use-case-dependency-graph.json](cyclonedx/usecases/cdx-use-case-dependency-graph.json) |  |
| 1.4 | [Provenance](https://cyclonedx.org/use-cases/#provenance) | [cyclonedx/usecases/cdx-use-case-provenance.json](cyclonedx/usecases/cdx-use-case-provenance.json) |  |
| 1.4 | [Pedigree](https://cyclonedx.org/use-cases/#pedigree) | [cyclonedx/usecases/cdx-use-case-pedigree.json](cyclonedx/usecases/cdx-use-case-pedigree.json) |  |
| 1.4 | [Service definition](https://cyclonedx.org/use-cases/#service-definition) | [cyclonedx/usecases/cdx-use-case-service-defn.json](cyclonedx/usecases/cdx-use-case-service-defn.json) | A complete v1.4 "service" definition |
| 1.4 | [Properties](https://cyclonedx.org/use-cases/#properties--name-value-store) | [cyclonedx/usecases/cdx-use-case-provenance.json](cyclonedx/usecases/cdx-use-case-provenance.json) | name-value store |
| 1.4 | [Packaging and distribution](https://cyclonedx.org/use-cases/#packaging-and-distribution) | [cyclonedx/usecases/cdx-use-case-packaging-and-distribution.json](cyclonedx/usecases/cdx-use-case-packaging-and-distribution.json) |  |
| 1.4 | [Composition completeness](https://cyclonedx.org/use-cases/#composition-completeness) | [cyclonedx/usecases/cdx-use-case-composition-and-completeness.json](cyclonedx/usecases/cdx-use-case-composition-and-completeness.json) |  |
| 1.4 | [OpenChain conformance](https://cyclonedx.org/use-cases/#openchain-conformance) | [cyclonedx/usecases/cdx-use-case-openchain-conformance.json](cyclonedx/usecases/cdx-use-case-openchain-conformance.json) |  |
| 1.4 | [Vulnerability remediation](https://cyclonedx.org/use-cases/#vulnerability-remediation) | [cyclonedx/usecases/cdx-use-case-vulnerability-remediation.json](cyclonedx/usecases/cdx-use-case-vulnerability-remediation.json) |  |
| 1.4 | [Vulnerability exploitability](https://cyclonedx.org/use-cases/#vulnerability-exploitability) | [cyclonedx/usecases/cdx-use-case-vulnerability-exploitability.json](cyclonedx/usecases/cdx-use-case-vulnerability-exploitability.json) |  |
| 1.4 | [Security advisories](https://cyclonedx.org/use-cases/#security-advisories) | [cyclonedx/usecases/cdx-use-case-security-advisories.json](cyclonedx/usecases/cdx-use-case-security-advisories.json) |  |
| 1.4 | [External references](https://cyclonedx.org/use-cases/#external-references) | [cyclonedx/usecases/cdx-use-case-external-references.json](cyclonedx/usecases/cdx-use-case-external-references.json) | |

### Use case ideas

- bom-link (VEX, SaaSBOM)
- Service "known vuln." use case **
- SLSA Conformance (SPDX is looking into this)

---

## SPDX examples

For convenience, examples are copied locally from:

- https://github.com/spdx/spdx-examples

| Name | SPDXID | Example (SBOM) | Description | Notes |
| :-- | :-- | :-- | :-- | :-- |
| "hello" | "SPDXRef-Package-hello" | [spdx/example1/example1.json](spdx/example1/example1.json) | SBOM for binary "/build/hello" from single, "C" source file |  |
| "hello-src" | "SPDXRef-Package-hello-src" | [spdx/example2/example2-src.json](spdx/example2/example2-src.json.json) | "hello.c" with "Makefile" | |
| "hello-bin" | "SPDXRef-Package-hello-bin" | [spdx/example2/example2-bin.json](spdx/example2/example2-bin.json.json) | "hello" ("C" language) binary only | |
| "hello-go-src"| "SPDXRef-Package-hello-go-src" | [spdx/example5/example5-src.json](spdx/example5/example5-src.json.json) | "hello.go" with "Makefile" | |
| "hello-go-bin" | "SPDXRef-Package-hello-go-bin" | [spdx/example5/example5-bin.json](spdx/example5/example5-bin.json.json) | "hello" ("Go" language) binary only | |
| "hello-go-src" | "SPDXRef-Package-hello-go-src" | [spdx/example6/example6.json](spdx/example6/example6-src.json) | "hello.go" with "Makefile" | |
| "hello-go-bin" | "SPDXRef-Package-hello-go-bin" | [spdx/example6/example6.json](spdx/example6/example6-bin.json) | "hello" ("Go" language) binary only | |
| "go-lib" | "SPDXRef-Package-go.reflect" | [spdx/example6/example6.json](spdx/example6/example6-lib.json) | A "Go" package distribution containing other Go packages | This seems to be the unique aspect of Example 6. Source and binary seem to be there for completeness. |
