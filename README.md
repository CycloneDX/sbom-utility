[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# sbom-utility

This utility is designed to be an API platform used *primarily to validate CycloneDX or SPDX SBOMs* (encoded in JSON format) against versioned JSON schemas as published by their respective organizations.

More importantly, the utility enables validation of SBOMs against derivative, "customized" schemas that can be used to enforce further data requirements not captured in the "base" schemas (e.g., industry or company-specific schemas).

Specifically, the utility is able to parse standardized SBOM output (produced by your favorite tooling) and validate it using a known schema format (e.g., SPDX, CycloneDX) and version (e.g., "2.2", "1.4", etc.) as declared within the SBOM document itself (i.e., "inferred" or "implicit") or against "customized" JSON schemas you can specify on the command line (i.e., "explicit") or permanently configure as named schema variants.

In the future, we envision additional kinds of SBOMs (e.g., Function-as-a-Service (Serverless), Machine Learning (ML), etc.) with each again having different sets of data requirements and levels of maturity which will increase the need for domain-specific validation.

#### Functional priorities

The utility additionally supports commands that helps provide insight into contents of the SBOM.  These commands have been developed to support verification for some of the primary SBOM use cases (see https://cyclonedx.org/use-cases/).  Functional development has been prioritized to support those use cases that support legal, security and compliance analysis which are foundational.

Initially, such functionality is reflected in the `license` and `query` commands which to be able to extract or produce formatted reports from inherent knowledge of the CycloneDX format.

The `license` command, for example, has many options and configurations to not only produce raw JSON output of license data, but also produce summarized reports in many human-readable formats (e.g., text, csv, markdown). Furthermore, the license command is able to apply configurable "usage policies" for the licenses identified in the reports.

The `query` command functionality is geared towards a SBOM-format aware SQL-style query that could be used to generate customized reports/views into the SBOM data for any use case.

Further commands and reports are planned that prioritize use cases that enable greater insight and analysis of the legal, security and compliance data captured in the SBOM such as **copyright** and **vulnerability** (VEX) information.

#### Design considerations

The utility itself is written in `Go` to advantage the language's built-in typing enforcement and memory safe features and its ability to be compiled for a wide range of architectures.

The utility also is designed to produce output formats (e.g., JSON) and handle exit codes consistently to make it immediately useful standalone or as part of automated Continuous Integration (CI) tool chains.

---

## Index

- [Installation](#installation)
- [Running](#running)
  - [Commands](#commands) - validate, license, query, schema, etc.
  - [Exit codes](#exit-codes)
  - [Quiet mode](#quiet-mode)
- [Contributing](#contributing)
  - [TODO list](#todo-list)
  - [Priority features](#priority-features)
- [Development](#development)
  - [Prerequisites](#prerequisites)
  - [Building](#building)
  - [Running from source](#running-from-source)
  - [Supporting new SBOM formats and schema versions](#supporting-new-sbom-formats-and-schema-versions)
  - [VSCode](#vscode)
- [Testing](#testing)
  - [Authoring tests](#authoring-tests)
  - [Running tests](#running-tests)
- [References](#references)

---

### Installation

Since the utility comes with a default configuration file and input schemas ready-mde for both SPDX and CycloneDX validation, the best way to install it (at this time) is to clone the entirety of the repository and then [build it](#building) using the `Makefile`.

Over time, we hope to be able to create a release process for the binary with just the necessary supporting files, but at this time achieving the validation function is tactically important.

```bash
git clone git@github.ibm.com:Supply-Chain-Security/sbom-utility.git
```

---

## Running

Currently, you must build an executable for your local system. See the [Prerequisites](#prerequisites) and [Building](#building) sections under [Development](#development) for details.

### Commands

Currently, the utility supports the following commands:

- [validate](#validate)
- [schema](#schema)
- [license](#license)
- [query](#query)
- [help](#help)

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

### Schema

You can verify which formats and schemas are available for validation by using the `schema` command:

```bash
$ ./sbom-utility schema

Format     Schema    Variant
------     ------    -------
SPDX       SPDX-2.3  (latest)
SPDX       SPDX-2.2  2.2.1
SPDX       SPDX-2.2  (latest)
CycloneDX  1.2       (latest)
CycloneDX  1.2       strict
CycloneDX  1.3       (latest)
CycloneDX  1.3       strict
CycloneDX  1.4       (latest)
CycloneDX  1.3       custom-dev
CycloneDX  1.4       custom-dev
CycloneDX  1.4       custom-rel
```

#### Adding schemas

Entries for new or "custom" schemas can be added to the `config.json` file simply by adding a new entry schema entry within the pre-defined format definitions.

These new entries will tell the schema loader where to find the new schema locally, relative to the utility's executable.

#### Embedding schemas

If you wish to have the new schema *embedded in the executable*, simply add it to the project's `resources` subdirectory following the format and version-based directory structure.

For details see "[Supporting new SBOM formats and schema versions](#supporting-new-sbom-formats-and-schema-versions)" section.

---

### Validate

Validating the "juice shop" SBOM (CycloneDX 1.2) example provided in this repository using a "built" (i.e., `make build`) binary:

```bash
$ ./sbom-utility validate -i examples/cyclonedx/BOM/juice-shop-11.1.2/bom.json

[INFO] : Unmarshalling file `examples/cyclonedx/BOM/juice-shop-11.1.2/bom.json`...
[INFO] : Successfully Opened: `examples/cyclonedx/BOM/juice-shop-11.1.2/bom.json`
[INFO] : Determining file's sbom format and version...
[INFO] : Loading schema `schema/cyclonedx/1.2/bom-1.2.schema.json`...
[INFO] : Schema `schema/cyclonedx/1.2/bom-1.2.schema.json` loaded.
[INFO] : Validating `examples/cyclonedx/BOM/juice-shop-11.1.2/bom.json`...
[INFO] : Valid: `true`
```

You can also verify the [exit code](#exit-codes) from the validate command:

```bash
$ echo $?
0  // no error (valid)
```

#### Validating using "custom" schema variants

The validation command will use the declared format and version found within the SBOM JSON file itself to lookup the default (latest) matching schema version (as declared in`config.json`; however, if variants of that same schema (same format and version) are declared, they can be requested via the `--variant` command line flag:

```bash
$ ./sbom-utility validate -i test/cyclonedx/cdx-1-4-mature-example-1.json --variant custom-dev
```

If you run the sample command above, you would see several "custom" schema errors resulting in an invalid SBOM determination.

```text
[INFO] : Unmarshalling file `test/cyclonedx/cdx-1-4-mature-example-1.json`...
[INFO] : Successfully Opened: `test/cyclonedx/cdx-1-4-mature-example-1.json`
[INFO] : Determining file's sbom format and version...
[INFO] : Loading schema `schema/cyclonedx/1.4/bom-1.4-ibm-development.schema.json`...
[INFO] : Schema `schema/cyclonedx/1.4/bom-1.4-ibm-development.schema.json` loaded.
[INFO] : Validating `test/cyclonedx/cdx-1-4-mature-example-1.json`...
[INFO] : Valid: `false`
[ERROR] validate.go(133) cmd.processValidationResults(): invalid SBOM: schema errors found (test/cyclonedx/cdx-1-4-mature-example-1.json):
(11) Schema errors detected (use `--debug` for more details):
	1. Type: [contains], Field: [metadata.properties], Description: [At least one of the items must match]
	Failing object: [[
	  {
	    "name": "urn:example.com:classification",
	    "value": " ... (truncated)
	2. Type: [pattern], Field: [metadata.properties.0.name], Description: [Does not match pattern '^urn:ibm:legal:disclaimer$']
	Failing object: ["urn:example.com:classification"]
	3. Type: [const], Field: [metadata.properties.0.value], Description: [metadata.properties.0.value does not match: ... (truncated)]
  ...
```

For example, the first schema error indicates a missing (required) property object where the second error specifies that the property should have a `name` field with value `"urn:example.com:classification"` which should have been paired with a predetermined `value`. In this case the `value` should have been a constant (that did not validate against schema regex).

---

### License

This command is used to aggregate and summarize software, hardware and data license information included in the SBOM. It can also be used to further display license usage policies for components based upon concluded by SPDX license identifier, license family or logical license expressions.

The `license` command supports the following subcommands:

- [list](#list-subcommand) - list or create a summarized report of licenses found in input SBOM.
- [policy](#policy-subcommand) - list user configured license policies by SPDX license ID and/or license family name.

##### Format flag

Use the `--format` flag on the `license list` or `license policy` subcommands  to choose one of the supported output formats:

- **Text** (default): `--format text`
- **Comma Separated Value (CSV)** `--format csv` flag:
- **Markdown** (table): `--format md`

##### Output flag

Use the `-o <filename>` (or `--output-file`) flag to send the (formatted) output to a file.

For example, output a license summary for an SBOM to a file named `output.txt`:

```bash
$ ./sbom-utility license list -i test/cyclonedx/cdx-1-3-license-list.json -o output.txt --summary

[INFO] : Creating output file: `output.txt`...
[INFO] : Unmarshalling file `test/cyclonedx/cdx-1-3-license-list.json`...
[INFO] : Successfully Opened: `test/cyclonedx/cdx-1-3-license-list.json`
[INFO] : Determining file's sbom format and version...
[INFO] : Scanning document for licenses...
[INFO] : Outputting summary (`txt` format)...
[INFO] : Closed output file: `output.txt`
```

---

#### `list` subcommand

This subcommand will emit a list of all licenses found in and SBOM (defaults to `json` format):

```bash
$ ./sbom-utility license list -i examples/cyclonedx/BOM/juice-shop-11.1.2/bom.json
```

 The output will be an array of CycloneDX `LicenseChoice` data structures.  For example, you would see licenses identified using SPDX IDs, license expressions (of SPDX IDs) or ones with "names" of licenses that do not necessarily map to a canonical SPDX ID along with the actual base64-encoded license or legal text.

 For example, the sample output output below shows the types of data you will see:

```json
[
    {
        "license": {
            "id": "MIT",
            "name": "",
            "text": {
                "contentType": "",
                "encoding": "",
                "content": ""
            },
            "url": ""
        },
        "expression": ""
    },
    {
        "license": {
            "id": "",
            "name": "",
            "text": {
                "contentType": "",
                "encoding": "",
                "content": ""
            },
            "url": ""
        },
        "expression": "Apache-2.0 AND (MIT OR GPL-2.0-only)"
    },
    {
        "license": {
            "id": "",
            "name": "Apache 2",
            "text": {
                "contentType": "text/plain",
                "encoding": "base64",
                "content": "CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEFwYWNoZSBMaWNlbnNlCiAgICAgICAgICAgICAgICAgICAgICAgICAgIFZlcnNpb24 ..."
            },
            "url": "https://www.apache.org/licenses/LICENSE-2.0.txt"
        },
        "expression": ""
    },
    ...
]
```

##### Summary flag

Use the `--summary` flag on the `license list` command to produce a summary report in `txt` (default) format as well as policy determination based upon the `license.json` declarations.

##### Summary policy column

The values for the `policy` column are derived from the `license.json` policy configuration file which the utility looks for in the execution root directory.

- *A policy of `UNDEFINED` indicates that `license.json` provided no entry that matched the declared license (`id` or `name`) in the SBOM.*

###### Text format example (default)

```bash
$ ./sbom-utility license list -i test/cyclonedx/cdx-1-3-license-list.json --summary

Policy        Type        ID/Name/Expression                    Component(s)      BOM ref.                            Document location
------        ----        ------------------                    ------------      --------                            -----------------
needs-review  name        UFL                                   ACME Application  pkg:app/sample@1.0.0                metadata.component
allow         expression  Apache-2.0 AND (MIT OR BSD-2-Clause)  Library B         pkg:lib/libraryB@1.0.0              components
needs-review  id          GPL-3.0-only                          Library D         pkg:lib/libraryD@1.0.0              components
allow         id          Apache-1.0                            Library E         pkg:lib/libraryE@1.0.0              components
needs-review  name        GPL                                   Library H         pkg:lib/libraryH@1.0.0              components
allow         name        BSD                                   Library J         pkg:lib/libraryJ@1.0.0              components
allow         id          Apache-2.0                            N/A               N/A                                 metadata.licenses
allow         id          Apache-2.0                            Library A         pkg:lib/libraryA@1.0.0              components
allow         id          Apache-2.0                            Library F         pkg:lib/libraryF@1.0.0              components
allow         id          MIT                                   ACME Application  pkg:app/sample@1.0.0                metadata.component
allow         id          MIT                                   Library A         pkg:lib/libraryA@1.0.0              components
allow         name        Apache                                Library B         pkg:lib/libraryB@1.0.0              components
needs-review  id          GPL-2.0-only                          Library C         pkg:lib/libraryC@1.0.0              components
allow         name        CC-BY-NC                              Library G         pkg:lib/libraryG@1.0.0              components
needs-review  name        AGPL                                  Library J         pkg:lib/libraryJ@1.0.0              components
UNDEFINED     id          ADSL                                  Foo               service:example.com/myservices/foo  services
```

###### CSV format example

```bash
$ ./sbom-utility license list -i test/cyclonedx/cdx-1-3-license-list.json --summary --quiet --format csv

Policy,Type,ID/Name/Expression,Component(s),BOM ref.,Document location
allow,expression,Apache-2.0 AND (MIT OR BSD-2-Clause),Library B,pkg:lib/libraryB@1.0.0,components
needs-review,id,GPL-2.0-only,Library C,pkg:lib/libraryC@1.0.0,components
needs-review,id,GPL-3.0-only,Library D,pkg:lib/libraryD@1.0.0,components
allow,id,Apache-1.0,Library E,pkg:lib/libraryE@1.0.0,components
needs-review,name,GPL,Library H,pkg:lib/libraryH@1.0.0,components
allow,name,BSD,Library J,pkg:lib/libraryJ@1.0.0,components
UNDEFINED,id,ADSL,Foo,service:example.com/myservices/foo,services
allow,id,Apache-2.0,N/A,N/A,metadata.licenses
allow,id,Apache-2.0,Library A,pkg:lib/libraryA@1.0.0,components
allow,id,Apache-2.0,Library F,pkg:lib/libraryF@1.0.0,components
allow,id,MIT,ACME Application,pkg:app/sample@1.0.0,metadata.component
allow,id,MIT,Library A,pkg:lib/libraryA@1.0.0,components
needs-review,name,UFL,ACME Application,pkg:app/sample@1.0.0,metadata.component
allow,name,Apache,Library B,pkg:lib/libraryB@1.0.0,components
allow,name,CC-BY-NC,Library G,pkg:lib/libraryG@1.0.0,components
needs-review,name,AGPL,Library J,pkg:lib/libraryJ@1.0.0,components
```

---

#### `policy` subcommand

To view a report listing the contents of the current policy file (i.e., `license.json`) which contains an encoding of known software and data licenses by SPDX ID and license family along with a configurable usage policy (i.e., "allow", "deny" or "needs-review") use:

```bash
$ ./sbom-utility license policy

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

#### Query

This command allows you to perform SQL-like queries into JSON format SBOMs.  Currently, the command recognizes the `--select` and `--from` as well as the `--where` filter.

The `--from` clause value is applied to the JSON document object model and can return either a singleton JSON object or an array of JSON objects as a result.  This is determined by the last property value's type as declared in the schema.

The `--select` clause is then applied to the `--from` result set to only return the specified properties (names and their values).

If the result set is an array, the array entries can be reduced by applying the `--where` filter to ony return those entries whose specified field names match the supplied regular expression (regex).

**Note**: All `query` command results are returned as valid JSON documents.  This includes a `null` value for empty result sets.

#### Example: Select a JSON object

In this example, only the `--from` clause is needed to select an object.  The `--select` clause is omitted which is equivalent to using the "select all" wildcard character `*` which returns all fields and values from the object.

```bash
$ ./sbom-utility query -i test/cyclonedx/cdx-1-4-mature-example-1.json --from metadata.component
```
is equivalent to

```
$ ./sbom-utility query -i test/cyclonedx/cdx-1-4-mature-example-1.json --select * --from metadata.component
```

Sample output:

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

#### Example: Select fields from JSON object

In this example, the `--from` clause references the  singleton JSON object `component` found under the top-level `metadata` object. It then reduces the resultant JSON object to only return the `name` and `value` fields and their values as requested on the `--select` clause.

```bash
$ ./sbom-utility query --select name,version --from metadata.component -i examples/cyclonedx/BOM/juice-shop-11.1.2/bom.json
```

Sample output:

```json
{
  "name": "juice-shop",
  "version": "11.1.2"
}
```

#### Example: Filter result entries with a specified value

In this example, the `--where` filter will be applied to a set of `properties` results to only include entries that match the specified regex.

```bash
$ ./sbom-utility query -i test/cyclonedx/cdx-1-4-mature-example-1.json --from metadata.properties --where name=urn:example.com:classification
```

Sample output:

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
$ ./sbom-utility query -i test/cyclonedx/cdx-1-4-mature-example-1.json --select value --from metadata.properties --where name=urn:example.com:classification
```

```json
[
  {
    "value": "This SBOM is Confidential Information. Do not distribute."
  }
]
```

---

### Help

The utility supports the `help` command for the root command as well as any supported commands

For example, to list top-level (root command) help which lists the supported "Available Commands":

```bash
$ ./sbom-utility help
```

A specific command-level help listing is also available. For example, you can access the help for the `validate` command:

```bash
$ ./sbom-utility help validate
```

---

## Contributing

Contributions are welcome under the Apache 2.0 license.

### TODO list

The entirety of the code contains the tag "**TODO**" with comments of things that are features or improvements conceived while authoring the base functionality.  Most of these do not have active issues opened form them.

Feel free to "grep" for the "TODO" tag, open an issue and/or submit a draft PR.

#### Priority features

An ad-hoc list of featured "TODOs" geared at making the tool more accessible, extensible and useful especially around "core" commands such as validation.

- **Release automation** Support versioned, github releases of the utility (e.g., Makefile target, scripts, process docs.)
- **Embedded resources** Look to optionally embed a default `config.json` (format/schema config.), `license.json` (license policy config.) and `custom.json` (custom validation config.) files.
- **Merge command** Support merge of two (both validated) SBOMs with de-duplication and configurable. Please note that some method of normalization prior to merge will be necessary.
- **Remote Schema loading** Support using SBOM schema files that are remotely hosted  (network accessible) from known, trusted source locations (e.g., releases of SPDX, CycloneDX specification schemas). Note that the config file has an existing `url` field per entry that can be used for this purpose.
- **--orderby** Support ordering of query result sets by comparison of values from a specified field key.
- **license.json** Document license policy configuration policy structure and how to add entries relative to a CycloneDX `LicenseChoice` object for entries with SPDX IDs and those without.

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

**Note** The binary created using `make build` will be for the local system's operating system and architecture (i.e., `GOOS`, `GOARCH`).  This would effectively match what would be reported using the `uname -s -m` unix command when run on the same local system.

If you wish to build binaries for all supported combinations of `GOOS` and `GOARCH` values, use the `release` target (i.e., `make release`) which will produce named binaries of the form `sbom-utility-${GOOS}-${GOARCH}` under the `release` directory (e.g., `sbom-utility-darwin-amd64`).

```bash
$ make release

GOOS=darwin GOARCH=amd64 go build -ldflags "-X main.Version=latest -X main.Binary=sbom-utility" -o release/sbom-utility-darwin-amd64
GOOS=darwin GOARCH=arm64 go build -ldflags "-X main.Version=latest -X main.Binary=sbom-utility" -o release/sbom-utility-darwin-arm64
GOOS=linux GOARCH=amd64 go build -ldflags "-X main.Version=latest -X main.Binary=sbom-utility" -o release/sbom-utility-linux-amd64
GOOS=linux GOARCH=arm64 go build -ldflags "-X main.Version=latest -X main.Binary=sbom-utility" -o release/sbom-utility-linux-arm64
GOOS=windows GOARCH=amd64 go build -ldflags "-X main.Version=latest -X main.Binary=sbom-utility" -o release/sbom-utility-windows-amd64
GOOS=windows GOARCH=arm64 go build -ldflags "-X main.Version=latest -X main.Binary=sbom-utility" -o release/sbom-utility-windows-arm64

$ ls release

total 131680
drwxr-xr-x   8 User1  staff       256 Oct 27 14:43 .
drwxr-xr-x  27 User1  staff       864 Oct 27 14:43 ..
-rw-r--r--   1 User1  staff      7121 Oct 27 14:43 config.json
-rw-r--r--   1 User1  staff      1346 Oct 27 14:43 custom.json
-rw-r--r--   1 User1  staff     62532 Oct 27 14:43 license.json
-rwxr-xr-x   1 User1  staff  11336640 Oct 27 14:43 sbom-utility-darwin-amd64
-rwxr-xr-x   1 User1  staff  11146770 Oct 27 14:43 sbom-utility-darwin-arm64
-rwxr-xr-x   1 User1  staff  11495647 Oct 27 14:43 sbom-utility-linux-amd64
-rwxr-xr-x   1 User1  staff  11076025 Oct 27 14:43 sbom-utility-linux-arm64
-rwxr-xr-x   1 User1  staff  11416576 Oct 27 14:43 sbom-utility-windows-amd64
-rwxr-xr-x   1 User1  staff  10934272 Oct 27 14:43 sbom-utility-windows-arm64
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

**TODO**: Update the `Makefile's` `release` target to conditionally pulls the release version from environment variable values and only uses the hardcoded values as defaults when not found in the runtime build environment.

### Running from source

Developers can run using the current source code in their local branch using `go run main.go`. For example:

```bash
$ go run main.go validate -i test/cyclonedx/cdx-1-4-mature-example-1.json
```

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

### VSCode

This project was developed using VSCode and can be seamlessly loaded as a project.

#### Debugging globals

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

---

### Testing

#### Authoring tests

As the actual tests files, `config.json` as well as the schema definition files are loaded relative to the project root, you will need to assure you change the working directory when initializing any `_test.go` module. For example, in `cmd/validate_test.go` file, you would need to change the working directory one level back:

```go
wd, _ := os.Getwd()
last := strings.LastIndex(wd, "/")
os.Chdir(wd[:last])
```

The "cmd" package already has a ready-made method named `initTestInfrastructure()` in the `test.go` module that can be called during test module initialize to assure the proper working directory is setup to read any path-relative input files used by `go test` methods:

```go
func init() {
  initTestInfra()
}
```

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
go test github.com/scs/sbom-utility/cmd -v
```

run an individual test within the `cmd` package:

```bash
go test github.com/scs/sbom-utility/cmd -v -run TestCdx13MinRequiredBasic
```

#### Debugging go tests

Simply append the flags `--args --trace` or `--args --debug` to your `go test` command to enable trace or debug output for your designated test(s):

```bash
go test github.com/scs/sbom-utility/cmd -v --args --trace
```

#### Eliminating extraneous test output

Several tests will still output error and warning messages as designed.  If these messages are distracting, you can turn them off using the `--quiet` flag.

```bash
$ go test github.com/scs/sbom-utility/cmd -v --args --quiet
```

**Note**: Always use the `--args` flag of `go test` as this will assure non-conflict with built-in flags.

---

## References

### CycloneDX

- [CycloneDX Specification Overview](https://cyclonedx.org/specification/overview/)
- Specification (all versions): https://github.com/CycloneDX/specification
  - (JSON) Schemas: https://github.com/CycloneDX/specification/tree/master/schema
  - Examples: https://github.com/CycloneDX/sbom-examples

#### CycloneDX use cases

- [CycloneDX Use Cases](https://cyclonedx.org/use-cases/) (comprehensive)
  - [Inventory](https://cyclonedx.org/use-cases/#inventory) (PoC)
  - [License Compliance](https://cyclonedx.org/use-cases/#license-compliance) (PoC)
  - [Known Vulnerabilities](https://cyclonedx.org/use-cases/#known-vulnerabilities) (PoC)
- CycloneDX 1.4 Vulnerability Exploitability Exchange (VEX) BOM format
  - Overview: [https://cyclonedx.org/capabilities/vex/](https://cyclonedx.org/capabilities/vex/)
  - VEX examples: [https://github.com/CycloneDX/bom-examples/tree/master/VEX](https://github.com/CycloneDX/bom-examples/tree/master/VEX)

### SPDX

- GitHub: https://github.com/spdx
  - Specification: https://github.com/spdx/spdx-spec
  - Schemas: https://github.com/spdx/spdx-spec/tree/development/v2.2.2/schemas
- https://tools.spdx.org/app/convert/ - Used this to convert from tv format to json
  - NOTE: tool could not convert `example6-bin.spdx`; resulted in an error

### Software-Bill-of-Materials (SBOM)

- [FOSSA - Software Bill Of Materials: Formats, Use Cases, and Tools](https://fossa.com/blog/software-bill-of-materials-formats-use-cases-tools/)
- [NTIA - SBOM Minimum Requirements](https://www.ntia.doc.gov/blog/2021/ntia-releases-minimum-elements-software-bill-materials)
