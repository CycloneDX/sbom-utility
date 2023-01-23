<!--
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
-->

# CycloneDX schema delta by version

## Notable Version 1.4 changes

Changes are relative to CycloneDX version 1.3.


### Global changes

##### Removed $id keys from all objects

In schema version 1.3 and earlier, every object had an `"$id"` key with relative path (path fragments) as values.  These values conceptually could have been used to reference specific objects from the schema from other schemas (via some for of JPath).

However, use cases nor any known usages of the `$id` values ever emerged.  In fact, many `$id` values were accidentally duplicated over time and were no longer unique within the schema. After much discussion, all such fields were removed beginning in version 1.4.

#### General updates to field descriptions

Several descriptions have been updated to correct errors or provide more succinct wordage.  Below we will only describe description changes that potentially affect field usage (values).

##### "version" description

The version 1.4 schema description for the `version` field reads:

*"Whenever an existing BOM is modified, either manually or through automated processes, the version of the BOM SHOULD be incremented by 1. When a system is presented with multiple BOMs with identical serial numbers, the system SHOULD use the most recent version of the BOM. The default version is '1'."*

**Note**: Automated SBOM tools **SHOULD NOT** increment the `version` field.  If editing is necessary after publishing, a new serial number should be generated with a new `timestamp`.

### Changes by field

#### Document-level fields

Top-level document (metadata) field changes.

| change | name | type | constraints | notes |
| :-- | :-- | :-- | :-- | :-- |
| change | title | string | `"CycloneDX Software Bill of Materials Standard"` | formerly `"Bill-of-Material Specification"` |

#### Document properties fields

Document `.properties` field changes.

**Note** As of 1.4, all `array` properties now **do NOT allow** additional items  via the `"additionalItems": false` constraint (e.g., `components`, `services`, `externalReferences`, `dependencies`, `compositions`, etc. ).

| change | name | type | constraints | notes |
| :-- | :-- | :-- | :-- | :-- |
| add    | `$schema` | string | `"enum": [ "http://cyclonedx.org/schema/bom-1.4.schema.json"` ] | New field, but not required **TBD, why not** |
| change | `specVersion` | string | `"examples": ["1.4"]` | change to example only |
| add | [`vulnerabilities`](https://github.com/CycloneDX/specification/blob/82bf9e30ba3fd6413e72a0e66adce2cdf3354f32/schema/bom-1.4.schema.json#L92)) | array of `#/definitions/vulnerability` | | *Vulnerabilities identified in components or services.* |
| add | [`signature`](https://github.com/CycloneDX/specification/blob/82bf9e30ba3fd6413e72a0e66adce2cdf3354f32/schema/bom-1.4.schema.json#L100) | `#/definitions/signature` | | *Enveloped signature in [JSON Signature Format (JSF)](https://cyberphone.github.io/doc/security/jsf.html).* |

### Type definitions

**Note** This list includes only the key top-level type definitions and does not exhaustively include all sub-type definitions the top-level type references.

#### Updated definitions

The following list shows notable changes to existing type definitions.

**Note** As of 1.4, all type definitions now **do NOT allow** additional properties via the `"additionalProperties": false` constraint.

| updated definition | change | property name | property type | constraints | notes |
| :-- | :-- | :-- | :-- | :-- | :-- |
| `tools` | add | `externalReferences` | array of `"#/definitions/externalReference"` | `"additionalItems": false` | |
| `organizationalContact` | update | `email` | string | `"format": "idn-email"` | *New constraint* |
| `component` | update | N/A | `"required": [ ..., "name" ]` | `"name"` added to required fields |
| `component` | update | `bom-ref` | `"$ref": "#/definitions/refType"`| | type changed from `string` to `refType`. |
| `component` | add | `releaseNotes` | `"$ref": "#/definitions/releaseNotes"`| | *Specifies optional release notes.*</br>References new type `releaseNotes`. |
| `component` | add | `signature` | `"$ref": "#/definitions/signature"`| | [JSON Signature Format (JSF)](https://cyberphone.github.io/doc/security/jsf.html)</br>References new type `signature`. |
| `service` | update | `bom-ref` | `"$ref": "#/definitions/refType"`| | type changed from `string` to `refType`. |
| `service` | add | `releaseNotes` | `"$ref": "#/definitions/releaseNotes"`| | *Specifies optional release notes.*</br>References new type `releaseNotes`. |
| `service` | add | `signature` | `"$ref": "#/definitions/signature"`| | [JSON Signature Format (JSF)](https://cyberphone.github.io/doc/security/jsf.html)</br>References new type `signature`. |
| `compositions` | add | `signature` | `"$ref": "#/definitions/signature"`| | [JSON Signature Format (JSF)](https://cyberphone.github.io/doc/security/jsf.html)</br>References new type `signature`. |
| `externalReference` | update | `type` | `string` | `"enum": [..., "release-notes"]` | Value `"release-notes"` added to constraint enumeration. |
| `dependency` | update | `ref` | "$ref": `"#/definitions/refType"` | | type changed from `string` to `refType` |
| `dependency` | update | `dependsOn.items` | "$ref": `"#/definitions/refType"` | | | `items` type changed from `string` to `refType` |
| | | | | | |

#### New definitions

**Note** Most new type definitions are being referenced via the `$ref` JSON schema keyword.  For more information see [https://json-schema.org/understanding-json-schema/structuring.html](https://json-schema.org/understanding-json-schema/structuring.html)

| name | type | constraints | description |
| :-- | :-- | :-- | :-- |
| `refType` | string | *none* | *Identifier-DataType for interlinked elements.* |
| `localeType` | string | `"^([a-z]{2})(-[A-Z]{2})?$"` | *two character language code (ISO-639)* |
| `releaseType` | string | | *"The software versioning type. It is **RECOMMENDED** that the release type use one of `major`, `minor`, `patch`, `pre-release` (i.e., representative of semantic versioning (semver), or 'internal' (not for public consumption)* |
| `note` | `object` | | *with properties:</br>`"locale": localeType`, `"text": attachment` not described here* |
| `releaseNotes` | `object` | | *See definition below.* |
| `advisory` | `object` | | *with properties:</br>`"title": string`, `"url": string` not described here*</br>**TODO** url should not be string type. Raise issue with project. |
| `cwe` | integer | | *"Integer representation of a Common Weaknesses Enumerations (CWE).* |
| `severity` | string | `"enum": ["critical", "high", "medium", "low", "info", "none", "unknown" ]` | *"Textual representation of the severity of the vulnerability (relative to method)* |
| `scoreMethod` | string | `"enum": ["CVSSv2", "CVSSv3", "CVSSv31", "OWASP", "other" ]`| *Specifies the severity or risk scoring methodology or standard used.* |
| `impactAnalysisState` | string | `"enum": [ .. ]` | *Enumerated values not shown here* |
| `rating` | `object` | | *Properties not shown here* |
| `vulnerabilitySource` | `object` | | *Properties not shown here* |
| `affectedStatus` | `object` | `"enum": ["affected",     "unaffected", "unknown"]` | |
| `version` | `string` | `"minLength": 1, "maxLength": 1024`| |
| `range` | `string` | `"minLength": 1, "maxLength": 1024`| |
| `signature` | `"$ref": "jsf-0.82.schema.json#/definitions/signature"` | | *Enveloped signature in [JSON Signature Format (JSF)](https://cyberphone.github.io/doc/security/jsf.html).* |

#### `releaseNotes` object properties

Release notes represents a significant new set of data whose properties are summarized below.

| name | type | constraints | description |
| :-- | :-- | :-- | :-- |
| `type` | `releaseType` | | |
| `title` | `string` | | |
| `featuredImage` | `string` | `"format": "iri-reference"` | |
| `socialImage` | `string` | `"format": "iri-reference"` | |
| `description`| `string` | | |
| `timestamp`| `string` | `"format": "date-time"`| |
| `aliases`| array of `string` | | |
| `tags`| array of `string` | | |
| `resolves`| array of `"$ref": "#/definitions/issue"` | | |
| `properties`| array of `"$ref": "#/definitions/property"` | | |

#### `vulnerability` object properties

Vulnerability represents a significant new set of data whose properties are summarized below.

| name | type | constraints | description |
| :-- | :-- | :-- | :-- |
| `bom-ref` | `"#/definitions/refType"` | | |
| `id` | `string` | | |
| `description` | `string` | | |
| `detail` | `string` | | |
| `recommendation` | `string` | | |
| `created` | `string` | | |
| `published` | `string` | | |
| `updated` | `string` | | |
| `source` | `"#/definitions/vulnerabilitySource"` | | |
| `references` | array of `items` | | *Items (properties) not described here* |
| `credits` | array of `items` | | *Items (properties) not described here* |
| `ratings` | array of `"$ref": "#/definitions/rating"` | | |
| `cwes` | array  of `"$ref": "#/definitions/cwe"` | | |
| `advisories` | array of `"$ref": "#/definitions/advisory"` | | |
| `tools` | array of `"$ref": "#/definitions/tool"` | | |
| `analysis` | `object` | | *Items (properties) not described here*|
| `affects` | `object` | | *Items (properties) not described here* |
| `properties` | array of `"$ref": "#/definitions/property"` | | |
