[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# sbom-utility

This utility is designed to be an API platform used primarily to **validate CycloneDX or SPDX SBOMs** (encoded in JSON format) against versioned JSON schemas as published by their respective organizations or custom variants provided by organizations that have stricter requirements.

However, the utility seeks to provide a rich set of commands in support of [BOM use cases](#cyclonedx-use-cases) for insight, in the form of filterable reports, into key BOM data elements reflected in the names of their respective commands. The full list of supported commands, with links to their full descriptions, syntax and example:

- [license](#license) with [list](#list-subcommand) and [policy](#policy-subcommand) subcommands
- [query](#query)
- [resource](#resource)
- [schema](#schema)
- [vulnerability](#vulnerability)
- [validate](#validate)
- [help](#help)

---

## Index

- [Installation](#installation)
- [Running](#running)
- [Commands](#commands)
  - [Overview](#overview)
  - [Exit codes](#exit-codes)
  - [Quiet mode](#quiet-mode)
- [Design considerations](#design-considerations)
- [Development](#development)
  - [Prerequisites](#prerequisites)
  - [Building](#building)
  - [Running from source](#running-from-source)
  - [Adding SBOM formats, schema versions and variants](#adding-sbom-formats-schema-versions-and-variants)
  - [Debugging](#debugging)
    - [VSCode](#vscode)
- [Contributing](#contributing)
  - [TODO list](#todo-list)
  - [Priority features](#priority-features)
- [Testing](#testing)
  - [Authoring tests](#authoring-tests)
  - [Running tests](#running-tests)
- [Releasing](#releasing)
- [References](#references): [CycloneDX](#cyclonedx), [SPDX](#spdx)

---

### Installation

Download and decompress the correct archive file (i.e., `.tar` for Unix/Linux systems and `.zip` for Windows) for your target system's architecture and operating system from the releases page within this repository.

- https://github.com/CycloneDX/sbom-utility/releases

The archive will contain the following files:

- `sbom-utility` - binary executable
- `config.json` - required schema configuration file
- `license.json` - optional license policy configuration file
- `custom.json` *(experimental)* - optional custom validation configuration file
- `LICENSE` - the software license for the utility (i.e. Apache 2)
- `sbom-utility-<version>.sbom.json` - the Software Bill-of-Materials for the utility

---

## Running

For convenience, assure that the required `config.json` and optional `license.json` and `custom.json` configuration files are copied to the same directory as the executable.

By default, the executable attempts to load the rall configuration files from the same path where the executable is run from. If you choose to keep them in a different directory, you will have to supply their relative locations using command flags.

##### MacOS - Granting executable permission

On MacOS, the utility is not a registered Apple application and may warn you that it cannot open it the first time. If so, you will need to explicitly permit the executable to be "opened" on your system acknowledging it trusted.  This process is initiated from the Finder application by using `ctrl-click` on the executable file and agreeing using the "Open" button.

- See https://support.apple.com/guide/mac-help/open-a-mac-app-from-an-unidentified-developer-mh40616/mac

---

### Commands

#### Overview

Currently, the utility supports the following commands:

- **[license](#license)** used to produce listings or summarized reports on license data contained in a BOM.  Reports can be produced in many human-readable formats (e.g., text, csv, markdown) or extracted listings in `json` format. Furthermore, the license command is able to apply configurable "usage policies" for the licenses identified in the reports.

- **[query](#query)** is geared towards an SBOM format-aware (CycloneDX-only for now), SQL-style query that could be used to generate customized reports/views into the SBOM data for any use case when other resource-specific commands are not provided or fall short.

- **[resource](#resource)** provides views on the SBOM's inventory or resources including components and services with the ability to filter by common, required fields such as name, version and bom-ref using regular expressions (regex).

- **[schema](#schema)** lists the "built-in" set of schema formats, versions and variants supported by the `validation` command.
  - Customized JSON schemas can also be permanently configured as named schema "variants" within the utility's configuration file (see the `schema` command's [adding schemas](#adding-schemas) section).

- **[validate](#validate)** enables validation of SBOMs against their declared format (e.g., SPDX, CycloneDX) and version (e.g., "2.2", "1.4", etc.) using their JSON schemas.
  - Derivative, "customized" schemas can be referenced using the `--variant` flag (e.g., industry or company-specific schemas).
  - You can override an BOM's default version using the `--force` flag (e.g., test an SBOM output against a newer specification version).

- **[vulnerability](#vulnerability)** command is able to produce a filterable summary of vulnerabilities (containing high-level information of interest) from an SBOM's or independent CycloneDX Vulnerability Exploitability eXchange (VEX) file's declared vulnerability list.

#### Exit codes

All commands, such as `validate`, also return a numeric exit code (i.e., a POSIX exit code)  for use in automated processing where `0` indicates success and a non-zero value indicates failure of some kind designated by the number.

For example, in bash, you can use the following command after running the utility to see the last exit code:

```bash
$ echo $?
2
```

which return one of the following exit code values:

- `0`= no error (valid)
- `1`= application error
- `2`= validation error

#### Quiet mode

By default, the utility outputs informational and processing text as well as any results of the command to `stdout`.  If you wish to only see the command results (JSON) or report (tables) you can run any command in "quiet mode" by simply supplying the `-q` or `--quiet` flag.

---

### License

This command is used to aggregate and summarize software, hardware and data license information included in the SBOM. It can also be used to further display license usage policies for components based upon concluded by SPDX license identifier, license family or logical license expressions.

The `license` command supports the following subcommands:

- [list](#list-subcommand) - list or create a summarized report of licenses found in input SBOM.
  - [list with --summary](#summary-flag) - As full license information can be very large, a summary view is often most useful.
- [policy](#policy-subcommand) - list user configured license policies by SPDX license ID and/or license family name.

##### Format flag

Use the `--format` flag on the `license list` or `license policy` subcommands to choose one of the supported output formats:

- **list**: json (default), csv, md
- **list** with `--summary` flag : txt (default), csv, md
- **policy**:  txt (default), csv, md

##### Output flag

Use the `-o <filename>` (or its long form `--output-file`) flag to send the (formatted) output to a file.

For example, output a license summary for an SBOM to a file named `output.txt`:

```bash
./sbom-utility license list -i test/cyclonedx/cdx-1-3-license-list.json -o output.txt --summary
```

```bash
[INFO] Loading license policy config file: `license.json`...
[INFO] Creating output file: `output.txt`...
[INFO] Attempting to load and unmarshal file `test/cyclonedx/cdx-1-3-license-list.json`...
[INFO] Successfully unmarshalled data from: `test/cyclonedx/cdx-1-3-license-list.json`
[INFO] Determining file's SBOM format and version...
[INFO] Determined SBOM format, version (variant): `CycloneDX`, `1.3` (latest)
[INFO] Matching SBOM schema (for validation): schema/cyclonedx/1.3/bom-1.3.schema.json
[INFO] Scanning document for licenses...
[INFO] Outputting summary (`txt` format)...
[INFO] Closed output file: `output.txt`
```

---

#### `list` subcommand

This subcommand will emit a list of all licenses found in and SBOM (defaults to `json` format):

```bash
./sbom-utility license list -i examples/cyclonedx/BOM/juice-shop-11.1.2/bom.json
```

 The output will be an array of CycloneDX `LicenseChoice` data structures.  For example, you would see licenses identified using SPDX IDs, license expressions (of SPDX IDs) or ones with "names" of licenses that do not necessarily map to a canonical SPDX ID along with the actual base64-encoded license or legal text.

 For example, the output below shows the three types of license data you would see:

```json
[
    {
        "license": {
            "$comment": "by license `id",
            "id": "MIT",
            "name": "",
            "url": ""
        }
    },
    {
        "license": {
            "$comment": "by license `expression",
            "id": "",
            "name": "",
            "url": ""
        },
        "expression": "Apache-2.0 AND (MIT OR GPL-2.0-only)"
    },
    {
        "license": {
            "$comment": "by license `name` with full license encoding",
            "id": "",
            "name": "Apache 2",
            "text": {
                "contentType": "text/plain",
                "encoding": "base64",
                "content": "CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEFwYWNoZSBMaWNlbnNlCiAgICAgICAgICAgICAgICAgICAgICAgICAgIFZlcnNpb24 ..."
            },
            "url": "https://www.apache.org/licenses/LICENSE-2.0.txt"
        }
    },
    ...
]
```

##### Summary flag

Use the `--summary` flag on the `license list` command to produce a summary report in `txt` (default) format as well as policy determination based upon the `license.json` declarations.

##### Summary policy column

The values for the `policy` column are derived from the `license.json` policy configuration file which the utility looks for in the execution root directory.

- A policy of `UNDEFINED` indicates that `license.json` provided no entry that matched the declared license (`id` or `name`) in the SBOM.
- License expressions (e.g., `(MIT or GPL-2.0)`) with one term resolving to `UNDEFINED` and the the other term having a concrete policy will resolve to the "optimistic" policy for `OR` expressions and the "pessimistic" policy for `AND` expressions.  In addition, a warning of this resolution is emitted.

###### Text format example (default)

```bash
./sbom-utility license list -i test/cyclonedx/cdx-1-3-license-list.json --summary
```

```bash
usage-policy  license-type  license                               resource-name      bom-ref                             bom-location
------------  ------------  -------                               -------------      -------                             ------------
needs-review  id            ADSL                                  Foo                service:example.com/myservices/foo  services
needs-review  name          AGPL                                  Library J          pkg:lib/libraryJ@1.0.0              components
allow         name          Apache                                Library B          pkg:lib/libraryB@1.0.0              components
allow         id            Apache-1.0                            Library E          pkg:lib/libraryE@1.0.0              components
allow         id            Apache-2.0                            N/A                N/A                                 metadata.licenses
allow         id            Apache-2.0                            Library A          pkg:lib/libraryA@1.0.0              components
allow         id            Apache-2.0                            Library F          pkg:lib/libraryF@1.0.0              components
allow         expression    Apache-2.0 AND (MIT OR BSD-2-Clause)  Library B          pkg:lib/libraryB@1.0.0              components
allow         name          BSD                                   Library J          pkg:lib/libraryJ@1.0.0              components
deny          name          CC-BY-NC                              Library G          pkg:lib/libraryG@1.0.0              components
needs-review  name          GPL                                   Library H          pkg:lib/libraryH@1.0.0              components
needs-review  id            GPL-2.0-only                          Library C          pkg:lib/libraryC@1.0.0              components
needs-review  id            GPL-3.0-only                          Library D          pkg:lib/libraryD@1.0.0              components
allow         id            MIT                                   ACME Application   pkg:app/sample@1.0.0                metadata.component
allow         id            MIT                                   Library A          pkg:lib/libraryA@1.0.0              components
UNDEFINED     invalid       NOASSERTION                           Library NoLicense  pkg:lib/libraryNoLicense@1.0.0      components
UNDEFINED     invalid       NOASSERTION                           Bar                service:example.com/myservices/bar  services
needs-review  name          UFL                                   ACME Application   pkg:app/sample@1.0.0                metadata.component
```

###### CSV format example

```bash
./sbom-utility license list -i test/cyclonedx/cdx-1-3-license-list.json --summary --quiet --format csv
```

```bash
usage-policy,license-type,license,resource-name,bom-ref,bom-location
allow,id,Apache-2.0,N/A,N/A,metadata.licenses
allow,id,Apache-2.0,Library A,pkg:lib/libraryA@1.0.0,components
allow,id,Apache-2.0,Library F,pkg:lib/libraryF@1.0.0,components
allow,expression,Apache-2.0 AND (MIT OR BSD-2-Clause),Library B,pkg:lib/libraryB@1.0.0,components
needs-review,id,GPL-3.0-only,Library D,pkg:lib/libraryD@1.0.0,components
needs-review,name,GPL,Library H,pkg:lib/libraryH@1.0.0,components
allow,id,MIT,ACME Application,pkg:app/sample@1.0.0,metadata.component
allow,id,MIT,Library A,pkg:lib/libraryA@1.0.0,components
allow,name,CC-BY-NC,Library G,pkg:lib/libraryG@1.0.0,components
needs-review,id,ADSL,Foo,service:example.com/myservices/foo,services
needs-review,name,UFL,ACME Application,pkg:app/sample@1.0.0,metadata.component
allow,name,Apache,Library B,pkg:lib/libraryB@1.0.0,components
allow,id,Apache-1.0,Library E,pkg:lib/libraryE@1.0.0,components
needs-review,name,AGPL,Library J,pkg:lib/libraryJ@1.0.0,components
UNDEFINED,invalid,NOASSERTION,Library NoLicense,pkg:lib/libraryNoLicense@1.0.0,components
UNDEFINED,invalid,NOASSERTION,Bar,service:example.com/myservices/bar,services
needs-review,id,GPL-2.0-only,Library C,pkg:lib/libraryC@1.0.0,components
allow,name,BSD,Library J,pkg:lib/libraryJ@1.0.0,components
```

#### Where flag filtering

The list command results can be filtered using the `--where` flag using the column names in the report. These include `usage-policy`, `license-type`, `license`, `resource-name`, `bom-ref` and `bom-location`.

The following example shows filtering of component licenses using the `license-type` column where the license was described as a `name` value:

```bash
./sbom-utility license list -i test/cyclonedx/cdx-1-3-license-list.json --summary --where license-type=name
```

```bash
usage-policy  license-type  license   resource-name     bom-ref                 bom-location
------------  ------------  -------   -------------     -------                 ------------
needs-review  name          AGPL      Library J         pkg:lib/libraryJ@1.0.0  components
allow         name          Apache    Library B         pkg:lib/libraryB@1.0.0  components
allow         name          BSD       Library J         pkg:lib/libraryJ@1.0.0  components
deny          name          CC-BY-NC  Library G         pkg:lib/libraryG@1.0.0  components
needs-review  name          GPL       Library H         pkg:lib/libraryH@1.0.0  components
needs-review  name          UFL       ACME Application  pkg:app/sample@1.0.0    metadata.component
```

In another example, the list is filtered by the `usage-policy` where the value is `needs-review`:

```bash
./sbom-utility license list -i test/cyclonedx/cdx-1-3-license-list.json --summary --where usage-policy=needs-review
```

```bash
usage-policy  license-type  license       resource-name     bom-ref                             bom-location
------------  ------------  -------       -------------     -------                             ------------
needs-review  id            ADSL          Foo               service:example.com/myservices/foo  services
needs-review  name          AGPL          Library J         pkg:lib/libraryJ@1.0.0              components
needs-review  name          GPL           Library H         pkg:lib/libraryH@1.0.0              components
needs-review  id            GPL-2.0-only  Library C         pkg:lib/libraryC@1.0.0              components
needs-review  id            GPL-3.0-only  Library D         pkg:lib/libraryD@1.0.0              components
needs-review  name          UFL           ACME Application  pkg:app/sample@1.0.0                metadata.component
```

---

#### `policy` subcommand

To view a report listing the contents of the current policy file (i.e., `license.json`) which contains an encoding of known software and data licenses by SPDX ID and license family along with a configurable usage policy (i.e., "allow", "deny" or "needs-review") use:

```bash
./sbom-utility license policy
```

```bash
Policy        Family           SPDX ID               Name                  Annotations
------        ------           -------               ----                  -----------
allow         0BSD             0BSD                  BSD Zero Clause Lice  APPROVED
allow         AFL              AFL-3.0               Academic Free Licens  APPROVED
needs-review  AGPL             AGPL-3.0-or-later     Affero General Publi  NEEDS-APPROVAL
needs-review  APSL             APSL-2.0              Apple Public Source   NEEDS-APPROVAL
allow         Adobe            Adobe-2006            Adobe Systems Incorp  APPROVED
allow         Apache           Apache-2.0            Apache License 2.0    APPROVED
...
```

##### Notes

- The policies the utility uses are defined in the `license.json` file which can be edited to add your organization's specific allow or deny-style license policies and notations.

---

### Query

This command allows you to perform SQL-like queries into JSON format SBOMs.  Currently, the command recognizes the `--select` and `--from` as well as the `--where` filter.

The `--from` clause value is applied to the JSON document object model and can return either a singleton JSON object or an array of JSON objects as a result.  This is determined by the last property value's type as declared in the schema.

The `--select` clause is then applied to the `--from` result set to only return the specified properties (names and their values).

If the result set is an array, the array entries can be reduced by applying the `--where` filter to ony return those entries whose specified field names match the supplied regular expression (regex).

**Note**: All `query` command results are returned as valid JSON documents.  This includes a `null` value for empty result sets.

#### Query Examples

##### Example: Select a JSON object

In this example, only the `--from` clause is needed to select an object.  The `--select` clause is omitted which is equivalent to using the "select all" wildcard character `*` which returns all fields and values from the object.

```bash
./sbom-utility query -i test/cyclonedx/cdx-1-4-mature-example-1.json --from metadata.component
```

is equivalent to using the wildcard character (which may need to be enclosed in single or double quotes depending on your shell):

```bash
./sbom-utility query -i test/cyclonedx/cdx-1-4-mature-example-1.json --select '*' --from metadata.component
```

```json
{
  "name": "Example Application v10.0.4",
  "bom-ref": "pkg:oci/example.com/product/application@10.0.4.0",
  "description": "Example's Do-It-All application",
  "externalReferences": [
    {
      "type": "website",
      "url": "https://example.com/application"
    }
  ],
  "hashes": [
    {
      "alg": "SHA-1",
      "content": "1111aaaa2222cccc3333dddd4444eeee5555ffff"
    }
  ],
  "licenses": [
    {
      "license": {
        "id": "Apache-2.0"
      }
    }
  ],
  ...
```

##### Example: Select fields from JSON object

In this example, the `--from` clause references the  singleton JSON object `component` found under the top-level `metadata` object. It then reduces the resultant JSON object to only return the `name` and `value` fields and their values as requested on the `--select` clause.

```bash
./sbom-utility query --select name,version --from metadata.component -i examples/cyclonedx/BOM/juice-shop-11.1.2/bom.json
```

```json
{
  "name": "juice-shop",
  "version": "11.1.2"
}
```

##### Example: Filter result entries with a specified value

In this example, the `--where` filter will be applied to a set of `properties` results to only include entries that match the specified regex.

```bash
./sbom-utility query -i test/cyclonedx/cdx-1-4-mature-example-1.json --from metadata.properties --where name=urn:example.com:classification
```

```json
[
  {
    "name": "urn:example.com:classification",
    "value": "This SBOM is Confidential Information. Do not distribute."
  }
]
```

additionally, you can apply a `--select` clause to simply obtain the matching entry's `value`:

```bash
./sbom-utility query -i test/cyclonedx/cdx-1-4-mature-example-1.json --select value --from metadata.properties --where name=urn:example.com:classification
```

```json
[
  {
    "value": "This SBOM is Confidential Information. Do not distribute."
  }
]
```

---

### Resource

The `resource` command is geared toward inspecting various resources types and their information from SBOMs against future maturity models being developed as part of the [OWASP Software Component Verification Standard (SCVS)](https://owasp.org/www-project-software-component-verification-standard/).  In the SCVS model, a "resource" is  the parent classification for software (components), services, Machine Learning (ML) models, data, hardware, tools and more.

Primarily, the command is used to generate lists of resources, by type, that are included in a CycloneDX SBOM by invoking `resource list`.

#### Where flag filtering

As of now, the list can be filtered by resource `type` which include `component` or `service`.  In addition, a `where` filter flag can be supplied to only include results where values match supplied regex.  Supported keys for the `where` filter include `name`, `version`, `type` and `bom-ref` *(i.e., all names of columns in the actual report)*.

#### Format flag

Use the `--format` flag on the to choose one of the supported output formats:

- txt (default), csv, md

#### Result sorting

Currently, all `resource list` command results are sorted by resource `type` then by resource `name` (required field).

#### Resource Examples

##### Example: list all

```bash
./sbom-utility resource list -i test/cyclonedx/cdx-1-3-resource-list.json --quiet
```

```bash
type       name               version  bom-ref
----       ----               -------  -------
component  ACME Application   2.0.0    pkg:app/sample@1.0.0
component  Library A          1.0.0    pkg:lib/libraryA@1.0.0
component  Library B          1.0.0    pkg:lib/libraryB@1.0.0
component  Library C          1.0.0    pkg:lib/libraryC@1.0.0
component  Library D          1.0.0    pkg:lib/libraryD@1.0.0
component  Library E          1.0.0    pkg:lib/libraryE@1.0.0
component  Library F          1.0.0    pkg:lib/libraryF@1.0.0
component  Library G          1.0.0    pkg:lib/libraryG@1.0.0
component  Library H          1.0.0    pkg:lib/libraryH@1.0.0
component  Library J          1.0.0    pkg:lib/libraryJ@1.0.0
component  Library NoLicense  1.0.0    pkg:lib/libraryNoLicense@1.0.0
service    Bar                         service:example.com/myservices/bar
service    Foo                         service:example.com/myservices/foo
```

##### Example: list by type service

This example uses the `type` flag to specific `service`.  The other valid type is `component`.  Future versions of CycloneDX schema will include more resource types such as "ml" (machine learning) or "tool".

```bash
./sbom-utility resource list -i test/cyclonedx/cdx-1-3-resource-list.json --type service --quiet
```

```bash
type     name    version  bom-ref
----     ----    -------  -------
service  Bar              service:example.com/myservices/bar
service  Foo              service:example.com/myservices/foo
```

##### Example: list with name match

This example uses the `where` filter on the `name` field. In this case we supply an exact "startswith" regex. for the `name` filter.

```bash
./sbom-utility resource list -i test/cyclonedx/cdx-1-3-resource-list.json --where "name=Library A" --quiet
```

```
type       name       version  bom-ref
----       ----       -------  -------
component  Library A  1.0.0    pkg:lib/libraryA@1.0.0
```

---

### Schema

You can verify which formats and schemas are available for validation by using the `schema` command:

```bash
./sbom-utility schema
```

```bash
Name                          Format     Version   Variant        File (local)                                     URL (remote)
----                          ------     -------   -------        ------------                                     ------------
CycloneDX v1.5 (development)  CycloneDX  1.5       (development)  schema/cyclonedx/1.5/bom-1.5-dev.schema.json     https://raw.githubusercontent.com/CycloneDX/specification/v1.5-dev/schema/bom-1.5.schema.json
CycloneDX v1.4                CycloneDX  1.4       (latest)       schema/cyclonedx/1.4/bom-1.4.schema.json         https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.4.schema.json
CycloneDX v1.3 (strict)       CycloneDX  1.3       (strict)       schema/cyclonedx/1.3/bom-1.3-strict.schema.json  https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.3-strict.schema.json
CycloneDX v1.3                CycloneDX  1.3       (latest)       schema/cyclonedx/1.3/bom-1.3.schema.json         https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.3.schema.json
CycloneDX v1.2 (strict)       CycloneDX  1.2       (strict)       schema/cyclonedx/1.2/bom-1.2-strict.schema.json  https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.2-strict.schema.json
CycloneDX v1.2                CycloneDX  1.2       (latest)       schema/cyclonedx/1.2/bom-1.2.schema.json         https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.2.schema.json
SPDX v2.3.1 (development)     SPDX       SPDX-2.3  (development)  schema/spdx/2.3.1/spdx-schema.json               https://raw.githubusercontent.com/spdx/spdx-spec/development/v2.3.1/schemas/spdx-schema.json
SPDX v2.3                     SPDX       SPDX-2.3  (latest)       schema/spdx/2.3/spdx-schema.json                 https://raw.githubusercontent.com/spdx/spdx-spec/development/v2.3/schemas/spdx-schema.json
SPDX v2.2.2                   SPDX       SPDX-2.2  (latest)       schema/spdx/2.2.2/spdx-schema.json               https://raw.githubusercontent.com/spdx/spdx-spec/v2.2.2/schemas/spdx-schema.json
SPDX v2.2.1                   SPDX       SPDX-2.2  (2.2.1)        schema/spdx/2.2.1/spdx-schema.json               https://raw.githubusercontent.com/spdx/spdx-spec/v2.2.1/schemas/spdx-schema.json
```

#### Adding schemas

Entries for new or "custom" schemas can be added to the `config.json` file simply by adding a new entry schema entry within the pre-defined format definitions.

These new entries will tell the schema loader where to find the new schema locally, relative to the utility's executable.

#### Embedding schemas

If you wish to have the new schema *embedded in the executable*, simply add it to the project's `resources` subdirectory following the format and version-based directory structure.

For details see "[Supporting new SBOM formats and schema versions](#supporting-new-sbom-formats-and-schema-versions)" section.

---

### Validate

This command will parse standardized SBOMs and validate it against its declared format and version (e.g., SPDX 2.2, CycloneDX 1.4). Custom  variants of standard JSON schemas can be used for validation by supplying the `--variant` name as a flag. Explicit JSON schemas can be specified using the `--force` flag.

##### Notes

- Use the [schema](#schema) command to list supported schemas formats, versions and variants.
- Customized JSON schemas can also be permanently configured as named schema "variants" within the utility's configuration file.

#### Validation Examples

##### Example: Using inferred format and schema

Validating the "juice shop" SBOM (CycloneDX 1.2) example provided in this repository.

```bash
./sbom-utility validate -i examples/cyclonedx/BOM/juice-shop-11.1.2/bom.json
```

```bash
[INFO] Loading license policy config file: `license.json`...
[INFO] Attempting to load and unmarshal file `examples/cyclonedx/BOM/juice-shop-11.1.2/bom.json`...
[INFO] Successfully unmarshalled data from: `examples/cyclonedx/BOM/juice-shop-11.1.2/bom.json`
[INFO] Determining file's SBOM format and version...
[INFO] Determined SBOM format, version (variant): `CycloneDX`, `1.2` (latest)
[INFO] Matching SBOM schema (for validation): schema/cyclonedx/1.2/bom-1.2.schema.json
[INFO] Loading schema `schema/cyclonedx/1.2/bom-1.2.schema.json`...
[INFO] Schema `schema/cyclonedx/1.2/bom-1.2.schema.json` loaded.
[INFO] Validating `examples/cyclonedx/BOM/juice-shop-11.1.2/bom.json`...
[INFO] SBOM valid against JSON schema: `true`
```

You can also verify the [exit code](#exit-codes) from the validate command:

```bash
$ echo $?
0  // no error (valid)
```

#### Example: Using "custom" schema variants

The validation command will use the declared format and version found within the SBOM JSON file itself to lookup the default (latest) matching schema version (as declared in`config.json`; however, if variants of that same schema (same format and version) are declared, they can be requested via the `--variant` command line flag:

```bash
./sbom-utility validate -i test/custom/cdx-1-4-test-custom-metadata-property-disclaimer-invalid.json --variant custom
```

If you run the sample command above, you would see several "custom" schema errors resulting in an invalid SBOM determination (i.e., `exit status 2`):

```text
[INFO] Loading license policy config file: `license.json`...
[INFO] Attempting to load and unmarshal file `test/custom/cdx-1-4-test-custom-metadata-property-disclaimer-invalid.json`...
[INFO] Successfully unmarshalled data from: `test/custom/cdx-1-4-test-custom-metadata-property-disclaimer-invalid.json`
[INFO] Determining file's SBOM format and version...
[INFO] Determined SBOM format, version (variant): `CycloneDX`, `1.4` (custom)
[INFO] Matching SBOM schema (for validation): schema/test/bom-1.4-custom.schema.json
[INFO] Loading schema `schema/test/bom-1.4-custom.schema.json`...
[INFO] Schema `schema/test/bom-1.4-custom.schema.json` loaded.
[INFO] Validating `test/custom/cdx-1-4-test-custom-metadata-property-disclaimer-invalid.json`...
[INFO] SBOM valid against JSON schema: `false`
[ERROR] invalid SBOM: schema errors found (test/custom/cdx-1-4-test-custom-metadata-property-disclaimer-invalid.json):
(3) Schema errors detected (use `--debug` for more details):
	1. Type: [contains], Field: [metadata.properties], Description: [At least one of the items must match]
	Failing object: [[
	  {
	    "name": "urn:example.com:disclaimer",
	    "value": "This ... (truncated)
	2. Type: [const], Field: [metadata.properties.0.value], Description: [metadata.properties.0.value does not match: "This SBOM is current as of the date it was generated and is subject to change."]
	Failing object: ["This SBOM is current as of the date it was generated."]
	3. Type: [number_all_of], Field: [metadata.properties], Description: [Must validate all the schemas (allOf)]
	Failing object: [[
	  {
	    "name": "urn:example.com:disclaimer",
	    "value": "This ... (truncated)
[INFO] document `test/custom/cdx-1-4-test-custom-metadata-property-disclaimer-invalid.json`: valid=[false]
exit status 2
```

Specifically, the output shows a first schema error indicating the failing JSON object; in this case, the CycloneDX property object with a `name` field with the value  `"urn:example.com:disclaimer"`. The second error indicates the property's `value` field SHOULD have had a constant value of `"This SBOM is current as of the date it was generated and is subject to change."` (as was required by the custom schema's regex). However, it was found to have only a partial match of `"This SBOM is current as of the date it was generated."`.

---

### Vulnerability

This command will extract basic vulnerability report data from an SBOM that has a "vulnerabilities" list or from a standalone VEX in CycloneDX format. It includes the ability to filter reports data by applying regex to any of the named column data.

**Note**: More column data and flags to filter results are planned.

#### Where flag filtering

In addition a `where` filter flag can be supplied to only include results where values match supplied regex.  Supported keys for the `where` filter include the following column names in the report (i.e., `id`, `bom-ref`, `created`
`published`, `updated`, `rejected` and `description`).

**Note**: filtering using `source.name` and `source.url` are coming soon

#### Format flag

Use the `--format` flag on the to choose one of the supported output formats:

- txt (default), csv, md

#### Result sorting

Currently, all `vulnerability list` command results are sorted by vulnerability `id` then by `created` date.

#### Vulnerability Examples

##### Simple list

```bash
./sbom-utility vulnerability list -i test/vex/cdx-1-3-example1-bom-vex.json --quiet
```

```bash
id              bom-ref  source.url  source.name                                      created                   published                 updated                   rejected  description
--              -------  ----------  -----------                                      -------                   ---------                 -------                   --------  -----------
CVE-2020-25649           NVD         https://nvd.nist.gov/vuln/detail/CVE-2020-25649  2020-12-03T00:00:00.000Z  2020-12-03T00:00:00.000Z  2023-02-02T00:00:00.000Z            com.fasterxml.jackson.core:jackson-databind is a library which contains the general-purpose data-binding functionality and tree-model for Jackson Data Processor.  Affected versions of this package are vulnerable to XML External Entity (XXE) Injection.
CVE-2022-42003           NVD         https://nvd.nist.gov/vuln/detail/CVE-2022-42003  2022-10-02T00:00:00.000Z  2022-10-02T00:00:00.000Z  2022-10-02T00:00:00.000Z            In FasterXML jackson-databind before 2.14.0-rc1, resource exhaustion can occur because of a lack of a check in primitive value deserializers to avoid deep wrapper array nesting, when the UNWRAP_SINGLE_VALUE_ARRAYS feature is enabled.
CVE-2022-42004           NVD         https://nvd.nist.gov/vuln/detail/CVE-2022-42004  2022-10-02T00:00:00.000Z  2022-10-02T00:00:00.000Z  2022-10-02T00:00:00.000Z            In FasterXML jackson-databind before 2.13.4, resource exhaustion can occur because of a lack of a check in BeanDeserializer._deserializeFromArray to prevent use of deeply nested arrays.
```

##### Simple list with where filter

```bash
./sbom-utility vulnerability list -i test/vex/cdx-1-3-example1-bom-vex.json --where id=2020 --quiet
```

```bash
id              bom-ref  source.url  source.name                                      created                   published                 updated                   rejected  description
--              -------  ----------  -----------                                      -------                   ---------                 -------                   --------  -----------
CVE-2020-25649           NVD         https://nvd.nist.gov/vuln/detail/CVE-2020-25649  2020-12-03T00:00:00.000Z  2020-12-03T00:00:00.000Z  2023-02-02T00:00:00.000Z            com.fasterxml.jackson.core:jackson-databind is a library which contains the general-purpose data-binding functionality and tree-model for Jackson Data Processor.  Affected versions of this package are vulnerable to XML External Entity (XXE) Injection.
```

---

### Help

The utility supports the `help` command for the root command as well as any supported commands

For example, to list top-level (root command) help which lists the supported "Available Commands":

```bash
./sbom-utility help
```

A specific command-level help listing is also available. For example, you can access the help for the `validate` command:

```bash
./sbom-utility help validate
```

---

#### Functional priorities

The utility additionally prioritizes commands that help provide insight into contents of the SBOM to search for and report on missing (i.e., completeness) or specific data requirements (e.g.,   organization or customer-specific requirements).  In general, the goal of these prioritized commands is to support data verification for many of the primary SBOM use cases as identified by the CycloneDX community (see https://cyclonedx.org/use-cases/).  Functional development has focused on those use cases that verify inventory (resource identity), legal compliance (e.g., license), and security analysis (e.g., vulnerability) which are foundational to any SBOM.

---

### Design considerations

The utility itself is written in `Go` to advantage the language's built-in typing enforcement and memory safe features and its ability to be compiled for a wide range of target platforms and architectures.

The utility also is designed to produce output formats (e.g., JSON) and handle exit codes consistently to make it immediately useful standalone or as part of automated Continuous Integration (CI) tool chains for downstream use or inspection.

Further commands and reports are planned that prioritize use cases that enable greater insight and analysis of the legal, security and compliance data captured in the SBOM such as component **provenance** and **signage** (e.g., verifying resource identities by hashes or fingerprints).

In the future, we envision additional kinds of SBOMs (e.g., Hardware, Machine Learning (ML), Function-as-a-Service (Serverless), etc.) with each again having different data requirements and levels of maturity which will increase the need for domain-specific validation.  Specifically, this utility intends to support the work of the [OWASP Software Component Verification Standard (SCVS)](https://owasp.org/www-project-software-component-verification-standard/) which is defining a BOM Maturity Model (BMM).

---

### Development

#### Prerequisites

- Go v1.18 or higher: see [https://go.dev/doc/install](https://go.dev/doc/install)
- `git` client: see [https://git-scm.com/downloads](https://git-scm.com/downloads)

#### Building

To build an executable of the utility compatible with your local computer's architecture use the `build` target in the project's `Makefile`:

```bash
cd sbom-utility/
make build
```

The will produce a binary named `sbom-utility` with version set to `latest` in the project's `release` directory.

```bash
$ ls
-rwxr-xr-x   1 Matt  staff  11501122 Jan 24 08:29 sbom-utility
```

```bash
$ ./sbom-utility version
Welcome to the sbom-utility! Version `latest` (sbom-utility) (darwin/arm64)
```

**Note** The binary created using `make build` will be for the local system's operating system and architecture (i.e., `GOOS`, `GOARCH`).  This would effectively match what would be reported using the `uname -s -m` unix command when run on the same local system.

If you wish to build binaries for all supported combinations of `GOOS` and `GOARCH` values, use the `release` target (i.e., `make release`) which will produce named binaries of the form `sbom-utility-${GOOS}-${GOARCH}` under the `release` directory (e.g., `sbom-utility-darwin-amd64`).

#### Running from source

Developers can run using the current source code in their local branch using `go run main.go`. For example:

```bash
go run main.go validate -i test/cyclonedx/cdx-1-4-mature-example-1.json
```

#### Debugging

##### VSCode

This project was developed using VSCode and can be seamlessly loaded as a project.

##### Debugging globals

In order to see global variables while debugging a specific configuration, you can add the `"showGlobalVariables": true` to it within your `launch.json` config. file:

```json
        {
            "showGlobalVariables": true,
            "name": "Test name",
            "type": "go",
            "request": "launch",
            "mode": "debug",
            "program": "main.go",
            "args": ["validate", "-i", "test/cyclonedx/cdx-1-3-min-required.json","-t"]
        },
```

or add it globally to the `settings.json` file:

1. Use `Command-Shift-P` to open `settings.json`
2. Select "Preferences: Open Settings (JSON)"
3. Add the following block at the top level:

```json
"go.delveConfig": {
    "showGlobalVariables": true
},
```

**Note**: *The `showGlobalVariables` setting was only recently disabled as the default in VSCode as a stop-gap measure due to performance (loading) problems under Windows.*


#### Adding SBOM formats, schema versions and variants

The utility uses the [`config.json`](./config.json) file to lookup supported formats and their associated versioned schemas.  To add another SBOM format simply add another entry to the `format` array in the root of the document:

```json
{
            "canonicalName": "SPDX",
            "propertyKeyFormat": "SPDXID",
            "propertyKeyVersion": "spdxVersion",
            "propertyValueFormat": "SPDXRef-DOCUMENT",
            "schemas": [
                {
                   ...
                }
            ]
   ...
}
```

The value for `propertyKeyFormat` should be the exact name of key field that would appear in the JSON SBOM itself which can be used to confirm it is indeed a format match.  In addition, the corresponding value to match for that key should be declared in the `propertyValueFormat` value.

The fields `canonicalName`, `propertyKeyFormat`, `propertyKeyVersion`, and `propertyValueFormat` are required. The `format` object **MUST** have at least one valid `schema` object. The `schema` object appears as follows:

```json
{
     "version": "SPDX-2.2",
     "file": "file://schema/spdx/2.2.1/spdx-schema.json",
     "url": "https://raw.githubusercontent.com/spdx/spdx-spec/v2.2.1/schemas/spdx-schema.json",
     "strict": false,
     "latest": true,
     "variant": ""
},
```

- Add a copy of the JSON schema file locally in the project under the structure `resources/schema/<format>/<version>/<schema filename>`.
  - **Note** If the schema exists under the `resources` directory, it will automatically be embedded in in the executable binary when built using `go build` which includes using the project's `Makefile`.
- Assure **only one** `schema` object entry for a given format and version has the value `latest` set to `true`.  This latest schema will be used when the SBOM being validated does not have a clear version declared **or** used with the `--force latest` flag.
- If you have a customized or "variant" version of a schema (with the same format and version values) you wish to use for validation (e.g., a `corporate`or `staging` version with added requirements or for testing an unreleased version), you can create an entry that has the same `version` as another entry, but also declare its `variant` name *(non-empty value)*.  This value can be supplied on the commend line with the `--variant <variant name>` flag to force the validator to use it instead of the default *(empty variant value)*.



---

### Contributing

Contributions are welcome under the Apache 2.0 license.

#### TODO list

The entirety of the code contains the tag "**TODO**" with comments of things that are features or improvements conceived while authoring the base functionality.  Most of these do not have active issues opened form them.

Feel free to "grep" for the "TODO" tag, open an issue and/or submit a draft PR.

#### Priority features

An ad-hoc list of featured "TODOs" geared at making the tool more accessible, extensible and useful especially around "core" commands such as validation.

- **Embedded resources** Look to optionally embed a default `config.json` (format/schema config.), `license.json` (license policy config.) and `custom.json` (experimental, custom validation config.) files.
- **Merge command** Support merge of two (both validated) SBOMs with de-duplication and configurable. Please note that some method of normalization prior to merge will be necessary.
- **Remote Schema loading** Support using SBOM schema files that are remotely hosted  (network accessible) from known, trusted source locations (e.g., releases of SPDX, CycloneDX specification schemas). Note that the config file has an existing `url` field per entry that can be used for this purpose.
- **--orderby** Support ordering of query result sets by comparison of values from a specified field key.
- **license.json** Document license policy configuration JSON schema structure and how to add entries relative to a CycloneDX `LicenseChoice` object for entries with SPDX IDs and those without.
- **license.json** Add more widely-recognized licenses (both from SPDX identifier lists as well as those not recognized by the SPDX community).
- **Go libraries** Replace `go-prettyjson`, `go-multimap` libraries with alternatives that produce maintained releases.

---

### Supporting new SBOM formats and schema versions

The utility uses the [`config.json`](./config.json) file to lookup supported formats and their associated versioned schemas.  To add another SBOM format simply add another entry to the `format` array in the root of the document:

```json
{
            "canonicalName": "SPDX",
            "propertyKeyFormat": "SPDXID",
            "propertyKeyVersion": "spdxVersion",
            "propertyValueFormat": "SPDXRef-DOCUMENT",
            "schemas": [
                {
                   ...
                }
            ]
   ...
}
```

The value for `propertyKeyFormat` should be the exact name of key field that would appear in the JSON SBOM itself which can be used to confirm it is indeed a format match.  In addition, the corresponding value to match for that key should be declared in the `propertyValueFormat` value.

The fields `canonicalName`, `propertyKeyFormat`, `propertyKeyVersion`, and `propertyValueFormat` are required. The `format` object **MUST** have at least one valid `schema` object. The `schema` object appears as follows:

```json
{
  {
      "version": "SPDX-2.3",
      "variant": "",  // None
      "name": "SPDX v2.3",
      "file": "schema/spdx/2.3/spdx-schema.json",
      "development": "https://github.com/spdx/spdx-spec/blob/development/v2.3/schemas/spdx-schema.json",
      "url": "https://raw.githubusercontent.com/spdx/spdx-spec/development/v2.3/schemas/spdx-schema.json",
      "default": true
  },
},
```

- Add a copy of the JSON schema file locally in the project under the structure `resources/schema/<format>/<version>/<schema filename>`.
  - **Note** If the schema exists under the `resources` directory, it will automatically be embedded in in the executable binary when built using `go build` which includes using the project's `Makefile`.
- Assure **only one** `schema` object entry for a given format and version has the value `latest` set to `true`.  This latest schema will be used when the SBOM being validated does not have a clear version declared **or** used with the `--force latest` flag.
- If you have a customized or "variant" version of a schema (with the same format and version values) you wish to use for validation (e.g., a `corporate`or `staging` version with added requirements or for testing an unreleased version), you can create an entry that has the same `version` as another entry, but also declare its `variant` name *(non-empty value)*.  This value can be supplied on the commend line with the `--variant <variant name>` flag to force the validator to use it instead of the default *(empty variant value)*.

---

## Testing

### SBOM test files

The built-in `go test` command is used to execute all functional tests that appear in `*._test.go` files.  By default, `go test` executes tests within the same directory where its respective `*._test.go` file is located and sets that as the working directory. For example, tests in the `validate_test.go` file are executed from the `cmd` subdirectory. This is a problem as the actual test SBOM JSON test files are located relative the project root, one level higher, and would not be found.  In order to correct for that, the test working directory is automatically changed for all tests within the `TestMain` routine found in `root_test.go`.

### Running tests

The `Makefile` includes a `test` target for convenience which will use `go test` to run all tests found in all subdirectories:

```bash
$ make test
```

The `test_cmd` target will use run only the test found in the `cmd` package:

```bash
$ make test_cmd
```

#### Using go test

Example: running all tests in the `cmd` package:

```bash
go test github.com/CycloneDX/sbom-utility/cmd -v
```

Run in "quiet" mode to not see error test output:
```bash
go test github.com/CycloneDX/sbom-utility/cmd -v --quiet
```

run an individual test within the `cmd` package:

```bash
go test github.com/CycloneDX/sbom-utility/cmd -v -run TestCdx13MinRequiredBasic
```

#### Debugging go tests

Simply append the flags `--args --trace` or `--args --debug` to your `go test` command to enable trace or debug output for your designated test(s):

```bash
go test github.com/CycloneDX/sbom-utility/cmd -v --args --trace
```

#### Eliminating extraneous test output

Several tests will still output error and warning messages as designed.  If these messages are distracting, you can turn them off using the `--quiet` flag.

```bash
go test github.com/CycloneDX/sbom-utility/cmd -v --args --quiet
```

**Note**: Always use the `--args` flag of `go test` as this will assure non-conflict with built-in flags.

---

#### Releasing

##### GitHub

In order to initiate the release workflow, simply go to the release page of the repository:

- https://github.com/CycloneDX/sbom-utility/releases

and click on the `Draft a new release` button.  Follow the instructions to create a new version tag, provide an appropriate release title and description and `publish` the release.  The GitHub release workflow will be triggered automatically.

##### Local

For local development, you may choose to make a release on your machine using the `Makefile` directive `release`:

```bash
make release
```

```bash
ls release
total 131680
drwxr-xr-x   8 User1  staff       256 Jan 27 14:43 .
drwxr-xr-x  27 User1  staff       864 Jan 27 14:43 ..
-rw-r--r--   1 User1  staff      7121 Jan 27 14:43 config.json
-rw-r--r--   1 User1  staff      1346 Jan 27 14:43 custom.json
-rw-r--r--   1 User1  staff     62532 Jan 27 14:43 license.json
-rwxr-xr-x   1 User1  staff  11336640 Jan 27 14:43 sbom-utility-darwin-amd64
-rwxr-xr-x   1 User1  staff  11146770 Jan 27 14:43 sbom-utility-darwin-arm64
-rwxr-xr-x   1 User1  staff  11495647 Jan 27 14:43 sbom-utility-linux-amd64
-rwxr-xr-x   1 User1  staff  11076025 Jan 27 14:43 sbom-utility-linux-arm64
-rwxr-xr-x   1 User1  staff  11416576 Jan 27 14:43 sbom-utility-windows-amd64
-rwxr-xr-x   1 User1  staff  10934272 Jan 27 14:43 sbom-utility-windows-arm64
...
```

- *Please also note that the common `*.json` configuration files are also copied to the `release` directory.*

##### Versioning

to produce a release version you can set the following flags and invoke `go build` directly:

```bash
BINARY=sbom-utility
VERSION=latest
LDFLAGS=-ldflags "-X main.Version=${VERSION} -X main.Binary=${BINARY}"
$ go build ${LDFLAGS} -o ${BINARY}
```

**TODO**: Update the `Makefile's` `release` target to conditionally pull the release version from environment variable values and only uses the hardcoded values as defaults when not found in the runtime build environment.

---

## References

### CycloneDX

- [CycloneDX Specification Overview](https://cyclonedx.org/specification/overview/)
- GitHub: https://github.com/CycloneDX
  - Specifications (by branch): https://github.com/CycloneDX/specification
  - Schemas (all versions): https://github.com/CycloneDX/specification/tree/master/schema
  - Examples: https://github.com/CycloneDX/sbom-examples
- CycloneDX Tool Center : https://cyclonedx.org/tool-center/

#### CycloneDX use cases

- [CycloneDX Use Cases](https://cyclonedx.org/use-cases/) (comprehensive), including:
  - [Inventory](https://cyclonedx.org/use-cases/#inventory)
  - [License Compliance](https://cyclonedx.org/use-cases/#license-compliance)
  - [Known Vulnerabilities](https://cyclonedx.org/use-cases/#known-vulnerabilities)

- [CycloneDX Vulnerability Exploitability Exchange (VEX) format Overview](https://cyclonedx.org/capabilities/vex/)
  - Examples: https://github.com/CycloneDX/bom-examples/tree/master/VEX

### SPDX

- GitHub: https://github.com/spdx
  - Specifications (by branch): https://github.com/spdx/spdx-spec
  - Schemas (by branch):
    - https://github.com/spdx/spdx-spec/tree/development/v2.3.1/schemas
    - https://github.com/spdx/spdx-spec/tree/development/v2.3/schemas
    - https://github.com/spdx/spdx-spec/tree/development/v2.2.2/schemas
  - Examples: https://github.com/spdx/spdx-examples

- Tools
  - SPDX Online Tool: https://tools.spdx.org/app/
    - **Note** Used the [convert](https://tools.spdx.org/app/convert/) tool to convert SPDX examples from `.tv` format to `.json`; however, conversion of [`example6-bin.spdx`](https://github.com/spdx/spdx-examples/blob/master/example6/spdx/example6-bin.spdx) resulted in an error.

### Software-Bill-of-Materials (SBOM)

- [NTIA - SBOM Minimum Requirements](https://www.ntia.doc.gov/blog/2021/ntia-releases-minimum-elements-software-bill-materials)
- [CISA - Software Bill of Materials (SBOM)](https://www.cisa.gov/sbom)
- [FOSSA - Software Bill Of Materials: Formats, Use Cases, and Tools](https://fossa.com/blog/software-bill-of-materials-formats-use-cases-tools/)

#### Guides

- [FOSSA](https://fossa.com/)
  - "A Practical Guide to CycloneDX": https://fossa.com/cyclonedx