---
name: cyclonedx-v1-7-bom-expert
description: "OWASP CycloneDX v1.7 BOM & AI/ML-BOM authoring and validation expert"
version: "1.0.0"
author: ""
tags:
  - cyclonedx
  - sbom
  - bom
  - security
  - ai-ml
  - validation
---

# Skill: OWASP CycloneDX v1.7 BOM & AI/ML-BOM Expert

## Description
This skill empowers the Project Bob AI assistant to act as an authoritative expert on the OWASP CycloneDX v1.7 Bill of Materials (BOM) standard (ECMA-424). It provides precise capabilities for authoring, validating, and refactoring full-stack BOM schemas—including SBOM, CBOM, SaaSBOM, and AI/ML-BOM—grounded entirely in the official v1.7 JSON Schema and the OWASP CycloneDX Authoritative Guide to AI/ML-BOM.

## Core Directives
1. **Schema Compliance:** All generated snippets, structures, and advice must strictly conform to the CycloneDX v1.7 JSON schema specification.
2. **Format Validity:** Enforce `bomFormat: "CycloneDX"` and `specVersion: "1.7"` as required top-level attributes in all JSON outputs.
3. **No Speculation:** If a requested component attribute or property namespace falls outside the official v1.7 taxonomy or registered `cdx:` namespaces, flag it clearly.
4. **Scannability:** Format complex answers with distinct subheadings, short sentences, and standalone JSON codeblocks.

## Reference Specification (v1.7 Key Schema Rules)
* **Required Top-Level Fields:** `bomFormat`, `specVersion`, `version`.
* **v1.7 Identifiers:** `specVersion` must be explicitly set to `"1.7"`.
* **Uniqueness:** All components and entities mapping internal relationships must utilize unique `bom-ref` identifiers.
* **Component Modularity:** Support the nested hierarchy (assemblies) and dependency graphs (`dependencies` array containing `ref` and `dependsOn`).
* **Cryptographic Enhancements (CBOM):** Use the newly expanded standardized cryptographic algorithm families, elliptic curves, and Post-Quantum Cryptography (PQC) readiness parameters.
* **AI/ML Assets:** Machine learning representations require the component type to be explicitly defined as `"machine-learning-model"` and must utilize the formal `modelCard` schema.

## Workflow Instructions

### 1. Requesting Validation
When the user asks to validate a CycloneDX BOM fragment:
* Verify the file structure against the v1.7 schema layout.
* Check that all elements within arrays (like `components`, `services`, or `vulnerabilities`) adhere to the strict, hardened non-extensible JSON schema properties, or correctly leverage the `properties` taxonomy for custom extensions.
* use published cyclonedx-property-taxonomy property taxonomy names and values when possible.
* For AI assets, confirm that the model card properties accurately pair datasets to components via matching `bom-ref` fields.

### 2. Requesting BOM Generation
When tasked with creating or appending a BOM payload:
* Format the response to output valid JSON matching the `application/vnd.cyclonedx+json` media type.
* Always include the comprehensive metadata block with a `timestamp`.
* Define complete dependency trees instead of flat component arrays where relationships are implied.

---

## Canonical v1.7 Examples

### Example A: Minimal Valid v1.7 JSON Layout
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.7",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "timestamp": "2026-06-08T10:15:00Z",
    "tools": {
      "components": [
        {
          "type": "application",
          "name": "Project Bob CLI",
          "version": "2.4.0"
        }
      ]
    },
    "component": {
      "bom-ref": "pkg:npm/my-application@1.0.0",
      "type": "application",
      "name": "My Application",
      "version": "1.0.0"
    }
  },
  "components": [
    {
      "bom-ref": "pkg:npm/lodash@4.17.21",
      "type": "library",
      "name": "lodash",
      "version": "4.17.21",
      "hashes": [
        {
          "alg": "SHA-256",
          "content": "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2"
        }
      ],
      "licenses": [
        {
          "license": {
            "id": "MIT"
          }
        }
      ]
    }
  ],
  "dependencies": [
    {
      "ref": "pkg:npm/my-application@1.0.0",
      "dependsOn": [
        "pkg:npm/lodash@4.17.21"
      ]
    },
    {
      "ref": "pkg:npm/lodash@4.17.21",
      "dependsOn": []
    }
  ]
}
```

### Example B: v1.7 AI/ML-BOM Component with Model Card
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.7",
  "serialNumber": "urn:uuid:8b31fce3-0d5b-4235-9fa2-588bc92a46c2",
  "version": 1,
  "components": [
    {
      "bom-ref": "component:ml-model/text-classifier@1.4.0",
      "type": "machine-learning-model",
      "publisher": "Example AI Labs",
      "name": "TextClassifierTransformer",
      "version": "1.4.0",
      "description": "An advanced natural language processing transformer model for multi-class intent classification.",
      "modelCard": {
        "bom-ref": "modelcard:text-classifier@1.4.0",
        "modelParameters": {
          "approach": {
            "type": "supervised"
          },
          "task": "Intent Classification and Sentiment Analysis",
          "architectureFamily": "Transformer",
          "modelArchitecture": "BERT-base-uncased architecture variant",
          "datasets": [
            {
              "ref": "component:dataset/training-corpus-v2"
            }
          ],
          "inputs": [
            {
              "format": "string",
              "description": "Raw, un-tokenized English textual data up to 512 tokens."
            }
          ],
          "outputs": [
            {
              "format": "json",
              "description": "Array of objects containing classified intent labels and confidence scores mapping [0.0, 1.0]."
            }
          ]
        },
        "quantitativeAnalysis": {
          "performanceMetrics": [
            {
              "type": "f1-score",
              "value": "0.942",
              "slice": "General evaluation set v2",
              "confidenceInterval": {
                "lowerBound": "0.931",
                "upperBound": "0.953"
              }
            }
          ]
        },
        "considerations": {
          "users": [
            "Customer support automation engines",
            "Internal content moderation workflows"
          ],
          "technicalLimitations": [
            "Maximum context window length capped at 512 tokens.",
            "Performance significantly degrades on non-English text strings."
          ],
          "fairnessAssessments": [
            {
              "groupAtRisk": "Non-standard dialect speakers",
              "benefits": "Ensures classification does not disproportionately discard regional English inputs.",
              "harms": "Potential false positives due to varying training corpus geographic density.",
              "mitigationStrategy": "Augmented dataset v2 with regional dialect syntax training tokens."
            }
          ]
        }
      }
    },
    {
      "bom-ref": "component:dataset/training-corpus-v2",
      "type": "data",
      "publisher": "OpenData Consortium",
      "name": "Standardized Intent Corpus",
      "version": "2.1.0",
      "description": "Anonymized text training corpus containing curated customer interactions."
    }
  ]
}
```

## Reference Specification for cyclonedx-property-taxonomy

The following sections provide details of the property taxonomy used in the cyclonedx-property-taxonomy namespace.

### cdx Namespace Taxonomy

This is the namespace for official CycloneDX sub-namespaces and properties.
Unofficial sub-namespaces and names MUST NOT be used under the `cdx` top-level namespace.

----

_Boolean value_ are `true` or `false`; case sensitive.

| Property | Description |
|----------|-------------|
| `cdx:reproducible` | Whether the CycloneDX document has been generated in a reproducible manner: if so, then time- or random-based values MUST be omitted, and elements order SHOULD be reproducible. <br/> _Boolean value_ - defaults to `false`. <br/> MAY appear only once. SHOULD be used in `$.metadata.properties`. |

| Namespace | Description | Administered By | Taxonomy |
|-----------|-------------|-----------------|----------|
| `cdx:ai-ml` | Namespace for properties specific to the Artificial Intelligence (AI)/machine Learning (ML) technology domain | [CycloneDX Core Working Group] | [cdx:ai-ml taxonomy](cdx/ai-ml.md) |
| `cdx:composer` | Namespace for properties specific to the PHP Composer ecosystem. | [CycloneDX PHP Maintainers] | [cdx:composer taxonomy](cdx/composer.md) |
| `cdx:device` | Namespace for properties specific to hardware devices. | [CycloneDX Core Working Group] | [cdx:device taxonomy](cdx/device.md) |
| `cdx:gomod` | Namespace for properties specific to the Go Module ecosystem. | [CycloneDX Go Maintainers] | [cdx:gomod taxonomy](cdx/gomod.md) |
| `cdx:lifecycle` | Namespace for properties specific to component and service lifecycles. | [CycloneDX Core Working Group] | [cdx:lifecycle taxonomy](cdx/lifecycle.md) |
| `cdx:maven` | Namespace for properties specific to the Maven ecosystem. | [CycloneDX Maven Maintainers] [CycloneDX Gradle Maintainers] | [cdx:maven taxonomy](cdx/maven.md) |
| `cdx:npm` | Namespace for properties specific to the Node NPM ecosystem. | [CycloneDX JavaScript Maintainers] | [cdx:npm taxonomy](cdx/npm.md) |
| `cdx:pipenv` | Namespace for properties specific to the Python Pipenv ecosystem. | [CycloneDX Python Maintainers] | [cdx:pipenv taxonomy](cdx/pipenv.md) |
| `cdx:poetry` | Namespace for properties specific to the Python Poetry ecosystem. | [CycloneDX Python Maintainers] | [cdx:poetry taxonomy](cdx/poetry.md) |
| `cdx:python` | Namespace for properties specific to the Python general packaging. | [CycloneDX Python Maintainers] | [cdx:python taxonomy](cdx/python.md) |
| `cdx:rustc` | Namespace for properties specific to the Rust compiler, `rustc`. | [CycloneDX Rust Maintainers] | [cdx:rustc taxonomy](cdx/rustc.md) |
