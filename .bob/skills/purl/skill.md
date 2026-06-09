---
name: package-url-purl-format-standard-expert
description: "OWASP Package URL (PURL) format expert"
version: "1.0.0"
author: ""
tags:
  - purl
  - bom
  - package-url
  - package-identity
---

# Skill: Package URL (purl) Format & Ecosystem Standard Expert

## Description
This skill teaches the Project Bob AI assistant how to act as an authoritative expert on the Package URL (purl) specification (ECMA-427). It guarantees precise capabilities for generating, validating, parsed debugging, and verifying software component identifiers across all official package manager types—including version-control software (`github`), programming language environments (`golang`, `pypi`), and AI/ML asset registries (`huggingface` models and datasets). It seamlessly integrates with SBOM generation utilities to ensure dependency trees map to legitimate, normalized upstream ecosystem identifiers.

## Core Directives
1. **Grammar Adherence:** Every generated purl must strictly follow the canonical URL-like structure: `pkg:<type>/<namespace>/<name>@<version>?<qualifiers>#<subpath>`.
2. **Case Normalization:** Enforce strict rule normalization (e.g., lowercasing the `scheme` and `type`; lowercasing `pypi` names; while preserving case sensitivity for `maven`, `github`, or `huggingface`).
3. **No Mismatches:** Prohibit the invention of custom package managers. Force the user toward registered `purl-spec` types or the explicit fallback `pkg:generic`.
4. **Scannability:** Format parsing workflows with markdown tables detailing string transformations.

## Reference Specification (purl Component Layout)
* **`scheme`:** Constant string value literal `pkg` (Required).
* **`type`:** The package manager platform/ecosystem namespace string (Required).
* **`namespace`:** Name prefix like a Maven groupId, GitHub organization, Go module repository path, or Hugging Face author username (Optional/Required based on type).
* **`name`:** Core identifier of the library, module, or dataset repository (Required).
* **`version`:** Distinct cryptographic tag, semantic version, or commit hash (Optional but strongly encouraged).
* **`qualifiers`:** Key-value parameters separating deployment architecture, distribution types, or registry mirrors (Optional).
* **`subpath`:** Relative path segment navigating deep inside extracted files (Optional).

---

## Ecosystem Formatting Matrix



| Package Type | Namespace Requirement | Case Handling | Qualifier/Subpath Specifics | Canonical purl Example |
| :--- | :--- | :--- | :--- | :--- |
| **`npm`** | Optional (for scoped packages) | Lowercase name/namespace | None | `pkg:npm/%40angular/core@12.0.0` |
| **`pypi`** | Prohibited | **Strictly Lowercase**; replace underscores `_` with hyphens `-` | None | `pkg:pypi/django-filter@2.4.0` |
| **`maven`** | Required | Case-sensitive (GroupId) | `repository_url`, `classifier` | `pkg:maven/org.apache.commons/commons-lang3@3.12.0` |
| **`cargo`** | Prohibited | Case-sensitive | None | `pkg:cargo/rand@0.8.5` |
| **`golang`** | **Required** (Host directory path) | **Host portion lowercase**; path portion case-sensitive | `#` handles internal package subpaths | `pkg:golang/://github.com` |
| **`docker`** | Optional (`library` default) | Lowercase name/namespace | `repository_url`, `arch` | `pkg:docker/library/ubuntu@20.04?arch=amd64` |
| **`github`** | Required (Owner org/user) | Case-sensitive | `#` handles directory subpaths | `pkg:github/package-url/purl-spec@244fd47e07d1004` |
| **`huggingface`** | Optional (Defaults to root user) | Case-sensitive name/namespace | `version` **must** be a lowercased commit hash. | `pkg:huggingface/microsoft/deberta-v3-base@559062ad13d311b87b2c455e67dcd5f1c8f65111` |
| **`generic`** | Optional | Case-sensitive | `vcs_url`, `download_url` | `pkg:generic/openssl@1.1.1?download_url=https://openssl.org` |

---

## Specific Ecosystem Directives

### 1. Python Packages (`pkg:pypi`)
* **Case & Character Rules:** Names must be entirely lowercased. Any underscore `_` characters in the package name must be systematically replaced with a dash `-`.
* **Namespace Constraints:** Python package URLs strictly prohibit the use of namespaces.

### 2. Go Modules (`pkg:golang`)
* **Namespace Constraints:** The `namespace` field must contain the lowercased host-part and intermediate path elements matching the module's distribution layout (e.g., `://google.com` or `://github.com`).
* **Name & Sub-module Rules:** The `name` element represents the trailing name of the root module containing its own distinct `go.mod` layout descriptor.
* **Sub-paths:** If targeting an internal non-module package subdirectory beneath the nested module path root, append a trailing URL fragment symbol `#` to locate that target path.

### 3. Hugging Face Models & Datasets (`pkg:huggingface`)
* **Namespace Constraints:** Represents the model or dataset repository author or organization (e.g., `meta-llama`, `stanfordnlp`). It is optional if the asset is hosted on the global Hugging Face root channel.
* **Dataset Differentiation:** Since Hugging Face splits its platform into models and datasets, denote a dataset repository by utilizing standard CycloneDX component tags (`type: "data"`) or adding explicit metadata bindings, while keeping the primary asset namespace matching the registry layout.
* **Version Constraints:** The `version` block represents the Git commit revision hash. It **must** be converted to an entirely lowercased string before generating the code identifier.

---

## Workflow Instructions

### 1. Requesting Validation & Normalization
When processing a raw user purl string or array:
* **Step 1:** Extract the `type` element and immediately execute character percentage encoding checks (e.g., Go modules with deep path escape sequences or scoped npm packages like `@types/node` must represent the `@` symbol safely via URL encoding as `%40`).
* **Step 2:** Ensure version hashes passed for `pkg:huggingface` or name paths for `pkg:pypi` execute the mandatory lowercase mapping.
* **Step 3:** Format any structural errors into a concise, 2-line correction block mapping the input value to the normalized spec layout.

### 2. Converting Ecosystem Objects to purl
When an agent or client delivers loose ecosystem parameters:
* Map the object values precisely into the strict URL structure.
* Strip protocol elements from target package URLs, translating trailing metadata flags into standardized query `qualifiers` where applicable.

---

## Execution Examples

### Example A: Python (`pypi`) Case and Character Normalization
```text
Raw Parameters: Type: pypi, Name: Flask_SQLAlchemy, Version: 3.0.3
purl String:     pkg:pypi/flask-sqlalchemy@3.0.3
```

### Example B: Go (`golang`) Monorepo Module Mapping
```text
Raw Parameters: Type: golang, Namespace: ://google.com, Module Name: storage, Version: v1.30.1, Target Internal Subpath: any/internal/internalprotopb
purl String:     pkg:golang/://google.com/storage@v1.30.1#any/internal/internalprotopb
```

### Example C: Hugging Face Dataset Reference
```text
Raw Parameters: Type: huggingface, Owner: stanfordnlp, Dataset Name: imdb, Commit Hash: A84235F6088ECD3DD5FB5
purl String:     pkg:huggingface/stanfordnlp/imdb@a84235f6088ecd3dd5fb5
```
