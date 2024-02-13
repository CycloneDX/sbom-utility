[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# sbom-utility

This utility was designed to be an API platform to validate, analyze and edit **Bills-of-Materials (BOMs)**. Initially, it was created to validate **CycloneDX** or **SPDX-formatted** BOMs against versioned JSON schemas (as published by their respective standards communities) or customized schema variants designed by organizations that may have stricter compliance requirements.

The utility now includes a rich set of commands, listed below, such as **trim**, **patch** (IETF RFC 6902) and **diff** as well as commands used to create filtered reports, in various formats, using the utility's powerful, SQL-like **query** command capability.

Supported report commands can easily extract **license**, **license policy**, **vulnerability**, **component**, **service** and other BOM information enabling verification for most [BOM use cases](#cyclonedx-use-cases) as well as custom security and compliance requirements.

*Please note that the utility supports all BOM variants such as **Software** (SBOM), **Hardware** (HBOM), **Manufacturing** (MBOM), **AI/ML** (MLBOM), etc. that adhere to their respective schemas.*

## Command Overview

The utility supports the following commands:

- **[license](#license)**
  - **[list](#license-list-subcommand)** produce listings or summarized reports of license data contained in a BOM along with license "usage policy" determinations using the policies declared in the `license.json` file.
  - **[policy](#license-policy-subcommand)** - lists software and data license information and associated license usage policies as defined in the configurable `license.json` file.

- **[query](#query)** retrieves JSON data from BOMs using SQL-style query statements (i.e., `--select <data fields> --from <BOM object> --where <field=regex>`). The JSON data can be used to create custom listings or reports.

- **[resource](#resource)** produce filterable listings or summarized reports of resources, including components and services, from BOM data.

- **[schema](#schema)** lists the "built-in" set of schema formats, versions and variants supported by the `validation` command.
  - Customized JSON schemas can also be permanently configured as named schema "variants" within the utility's configuration file (see the `schema` command's [adding schemas](#adding-schemas) section).

- **[trim](#trim)** provide the ability to remove specified JSON information from the input JSON BOM document and produce output BOMs with reduced or targeted sets of information.  A SQL-like set of parameters allows for fine-grained specification of which fields should be trimmed from which document paths.

- **[validate](#validate)** enables validation of SBOMs against their declared format (e.g., SPDX, CycloneDX) and version (e.g., "2.3", "1.5", etc.) using their JSON schemas.
  - Derivative, **"customized" schemas** can be used for verification using the `--variant` flag (e.g., industry or company-specific schemas).
  - You can override an BOM's declared BOM version using the `--force` flag (e.g., verify a BOM against a newer specification version).

- **[vulnerability](#vulnerability)** produce filterable listings or summarized reports of vulnerabilities from BOM data (i.e., CycloneDX Vulnerability Exploitability eXchange (**VEX**)) data or independently stored CycloneDX Vulnerability Disclosure Report (**VDR**) data.

**Experimental commands**:

Feedback and helpful commits appreciated on the following commands which will be promoted after at least two point releases:

- **[diff](#diff)** : Shows the delta between two similar BOM versions in JSON (diff) patch format as defined by [IETF RFC 6902](https://datatracker.ietf.org/doc/html/rfc6902/).

- **[patch](#patch)** : Applies a JSON patch file, as defined by [IETF RFC 6902](https://datatracker.ietf.org/doc/html/rfc6902/), to an input JSON BOM file.

---

## Index

- [Installation](#installation)
- [Running](#running)
- [Commands](#commands)
  - [Exit codes](#exit-codes): (e.g., `0`: none, `1`: application, `2`: validation)
  - [Persistent flags](#persistent-flags) (e.g., `--format`, `--quiet`, `--where`, etc.)
  - [license](#license)
    - [list](#license-list-subcommand) subcommand: lists all license information found in the BOM
    - [policy](#license-policy-subcommand) subcommand: lists configurable license usage policies
  - [query](#query): extract JSON objects and fields from a BOM using SQL-like queries
  - [resource](#resource): list resource information by type (e.g., components, services)
  - [schema](#schema): list supported BOM formats, versions, variants
  - [trim](#trim): remove unnecessary fields and data from a BOM
  - [validate](#validate): BOM against declared or required schema
  - [vulnerability](#vulnerability): lists vulnerability summary information included in the BOM or VEX
  - [completion](#completion): generates command-line completion scripts for the utility
- [Experimental commands](#experimental-commands)
  - [diff](#diff): compares differences between two similar BOMs
  - [patch](#patch): patches BOMs using IETF RFC 6902 records.
- [Design considerations](#design-considerations)
- [Development](#development)
  - [Prerequisites](#prerequisites)
  - [Building](#building)
  - [Running from source](#running-from-source)
  - [Debugging](#debugging)
    - [VSCode](#vscode)
  - [Adding SBOM formats, schema versions and variants](#adding-sbom-formats-schema-versions-and-variants)
- [Contributing](#contributing)
  - [TODO list](#todo-list)
  - [Priority features](#priority-features)
- [Testing](#testing)
  - [Go test files](#go-test-files)
  - [Running tests](#running-tests)
- [Releasing](#releasing)
- [References](#references): [CycloneDX](#cyclonedx), [SPDX](#spdx)

---

### Installation

Download and decompress the correct archive file (i.e., `.tar` for Unix/Linux systems and `.zip` for Windows) for your target system's architecture and operating system from the releases page within this repository.

- [https://github.com/CycloneDX/sbom-utility/releases](https://github.com/CycloneDX/sbom-utility/releases)

The archive will contain the following files:

- `sbom-utility` - binary executable. This is all most need for non-customized configurations.
- `config.json` *(optional)* - copy of the default schema configuration file for optional customization (to be passed on the command line)
- `license.json` *(optional)* - copy of the default license policy configuration file for optional customization (to be passed on the command line)
- `custom.json` *(experimental)* - custom validation configuration file
- `LICENSE` - the software license for the utility (i.e. Apache 2)
- `sbom-utility-<version>.sbom.json` - a simple Software Bill-of-Materials (SBOM) for the utility

---

## Running

For convenience, the default `config.json` and optional `license.json` configuration files have been embedded in the executable and used if none are provided on the command line using the `--config-schema` or `--config-license` flags respectively.

When providing configuration files using command line flags, the executable attempts to load them from the same path where the executable is run from. If you choose to keep them in a different directory, you will have to supply their location relative to the executable along with the filename.

##### MacOS - Granting executable permission

On MacOS, the utility is not a registered Apple application and may warn you that it cannot open it the first time. If so, you will need to explicitly permit the executable to be "opened" on your system acknowledging it trusted.  This process is initiated from the Finder application by using `ctrl-click` on the executable file and agreeing using the "Open" button.

- See how to ["Open a Mac app from an unidentified developer"](https://support.apple.com/guide/mac-help/open-a-mac-app-from-an-unidentified-developer-mh40616/mac)

---

## Commands

This section provides detailed descriptions of all commands, their flags and examples. First we will cover how all commands generate consistent [exit codes](#exit-codes) and describe some of the  [persistent flags](#persistent-flags) supported by most commands.

For convenience, links to each command's section are here:

- [license](#license)
  - [list](#license-list-subcommand) subcommand
  - [policy](#license-policy-subcommand) subcommand
- [query](#query)
- [resource](#resource)
- [schema](#schema)
- [vulnerability](#vulnerability)
- [validate](#validate)
- [completion](#completion)
- [help](#help)

#### Exit codes

All commands return a numeric exit code (i.e., a POSIX exit code) for use in automated processing where `0` indicates success and a non-zero value indicates failure of some kind designated by the number.

The SBOM Utility always returns one of these 3 codes to accommodate logic in BASH (shell) scripting:

- `0`= no error (valid)
- `1`= application error
- `2`= validation error

##### Example: exit code

This example uses the `schema` list command to verify its exit code:

```bash
./sbom-utility schema list
```

verify the exit code:

```bash
echo $?
```

which returns `0` (zero) or "no error":

```bash
0
```

### Persistent flags

This section describes some of the important command line flags that apply to most of the utility's commands.

- [format flag](#format-flag): with `--format`
- [indent flag](#indent-flag): with `--indent`
- [input flag](#input-flag): with `--input` or `-i`
- [output flag](#output-flag): with `--output` or `-o`
- [quiet flag](#quiet-flag): with `--quiet` or `-q`
- [where flag](#where-flag-output-filtering): with `--where`

#### Format flag

All `list` subcommands support the `--format` flag with the following values:

- `txt`: text (tabbed tables)
- `csv`: Comma Separated Value (CSV), e.g., for spreadsheets
- `md`: Markdown, e.g., for GitHub

Some commands, which can output lists of JSON objects, also support JSON format using the `json` value.

##### Example: `--format` flag

This example uses the `--format` flag on the `schema` command to output in markdown:

```bash
./sbom-utility schema --format md -q
```

```md
|name|format|version|variant|file (local)|url (remote)|
|:--|:--|:--|:--|:--|:--|
|CycloneDX v1.5|CycloneDX|1.5|(latest)|schema/cyclonedx/1.5/bom-1.5.schema.json|https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.5.schema.json|
|CycloneDX v1.4|CycloneDX|1.4|(latest)|schema/cyclonedx/1.4/bom-1.4.schema.json|https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.4.schema.json|
|CycloneDX/specification/master/schema/bom-1.3-strict.schema.json|
|CycloneDX v1.3|CycloneDX|1.3|(latest)|schema/cyclonedx/1.3/bom-1.3.schema.json|https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.3.schema.json|
|CycloneDX/specification/master/schema/bom-1.2-strict.schema.json|
|CycloneDX v1.2|CycloneDX|1.2|(latest)|schema/cyclonedx/1.2/bom-1.2.schema.json|https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.2.schema.json|
|SPDX v2.3.1 (development)|SPDX|SPDX-2.3|development|schema/spdx/2.3.1/spdx-schema.json|https://raw.githubusercontent.com/spdx/spdx-spec/development/v2.3.1/schemas/spdx-schema.json|
|SPDX v2.3|SPDX|SPDX-2.3|(latest)|schema/spdx/2.3/spdx-schema.json|https://raw.githubusercontent.com/spdx/spdx-spec/development/v2.3/schemas/spdx-schema.json|
|SPDX v2.2.2|SPDX|SPDX-2.2|(latest)|schema/spdx/2.2.2/spdx-schema.json|https://raw.githubusercontent.com/spdx/spdx-spec/v2.2.2/schemas/spdx-schema.json|
|SPDX v2.2.1|SPDX|SPDX-2.2|2.2.1|schema/spdx/2.2.1/spdx-schema.json|https://raw.githubusercontent.com/spdx/spdx-spec/v2.2.1/schemas/spdx-schema.json|
```

### Indent flag

This flag supplies an integer to any command that encodes JSON output to determine how many spaces to indent nested JSON elements.  If not specified, the default indent is `4` (spaces).

#### Example: indent flag on the query command

```bash
./sbom-utility query --select name,version --from metadata.component -i examples/cyclonedx/SBOM/juice-shop-11.1.2/bom.json --indent 2 --quiet
```

output with `indent 2`:

```json
{
  "name": "juice-shop",
  "version": "11.1.2"
}
```

```bash
./sbom-utility query --select name,version --from metadata.component -i examples/cyclonedx/SBOM/juice-shop-11.1.2/bom.json --indent 6 --quiet
```

output with `indent 6`:

```json
{
      "name": "juice-shop",
      "version": "11.1.2"
}
```

#### Input flag

All `list` subcommands and the `validate` command support the `--input-file <filename>` flag (or its short-form `-i <filename>`) to declare file contents (i.e., BOM data) the commands will read and operate on.

#### Standard input (stdin)

All commands that support the input flag can also accept data from standard input or `stdin` by using the `-` (dash) character as the value instead of a filename.

##### Example of stdin using pipe

```bash
 cat examples/cyclonedx/SBOM/juice-shop-11.1.2/bom.json | ./sbom-utility resource list -i -
```

##### Example of stdin using redirect

```bash
./sbom-utility validate -i - < examples/cyclonedx/SBOM/juice-shop-11.1.2/bom.json
```

#### Output flag

All `list` subcommands and the `validate` command support the `--output-file <filename>` flag (or its short-form `-o <filename>`) to send formatted output to a file.

##### Example: `--output-file` flag

This example uses the `schema` command to output to a file named `output.txt` with format set to `csv`:

```bash
./sbom-utility schema --format csv -o output.csv
```

Verify the contents of `output.csv` contain CSV formatted output:

```bash
cat output.csv
```

```csv
Name,Format,Version,Variant,File (local),URL (remote)
CycloneDX v1.5 (development),CycloneDX,1.5,development,schema/cyclonedx/1.5/bom-1.5-dev.schema.json,https://raw.githubusercontent.com/CycloneDX/specification/v1.5-dev/schema/bom-1.5.schema.json
CycloneDX v1.4,CycloneDX,1.4,(latest),schema/cyclonedx/1.4/bom-1.4.schema.json,https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.4.schema.json
CycloneDX v1.3,CycloneDX,1.3,(latest),schema/cyclonedx/1.3/bom-1.3.schema.json,https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.3.schema.json
CycloneDX v1.2,CycloneDX,1.2,(latest),schema/cyclonedx/1.2/bom-1.2.schema.json,https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.2.schema.json
SPDX v2.3.1 (development),SPDX,SPDX-2.3,development,schema/spdx/2.3.1/spdx-schema.json,https://raw.githubusercontent.com/spdx/spdx-spec/development/v2.3.1/schemas/spdx-schema.json
SPDX v2.3,SPDX,SPDX-2.3,(latest),schema/spdx/2.3/spdx-schema.json,https://raw.githubusercontent.com/spdx/spdx-spec/development/v2.3/schemas/spdx-schema.json
SPDX v2.2.2,SPDX,SPDX-2.2,(latest),schema/spdx/2.2.2/spdx-schema.json,https://raw.githubusercontent.com/spdx/spdx-spec/v2.2.2/schemas/spdx-schema.json
SPDX v2.2.1,SPDX,SPDX-2.2,2.2.1,schema/spdx/2.2.1/spdx-schema.json,https://raw.githubusercontent.com/spdx/spdx-spec/v2.2.1/schemas/spdx-schema.json
```

- **Note**: You can verify that `output.csv` loads within a spreadsheet app like MS Excel.

#### Quiet flag

All commands support the `--quiet` flag. By default, the utility outputs informational (INFO), warning (WARNING) and error (ERROR) text along with the  actual command results to `stdout`.  If you wish to only see the command results (JSON) or report (tables) you can run any command in "quiet mode" by simply supplying the `--quiet` or its short-form `-q` flag.

##### Example: `--quiet` flag

This example shows the `--quiet` flag being used on the `schema` command to turn off or "quiet" any informational output so that only the result table is displayed.

```bash
./sbom-utility schema --quiet
```

```bash
name                          format     version   variant      file (local)                                     url (remote)
----                          ------     -------   -------      ------------                                     ------------
CycloneDX v1.5                CycloneDX  1.5       (latest)     schema/cyclonedx/1.5/bom-1.5.schema.json         https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.5.schema.json
CycloneDX v1.4                CycloneDX  1.4       (latest)     schema/cyclonedx/1.4/bom-1.4.schema.json         https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.4.schema.json
CycloneDX v1.3                CycloneDX  1.3       (latest)     schema/cyclonedx/1.3/bom-1.3.schema.json         https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.3.schema.json
CycloneDX v1.2                CycloneDX  1.2       (latest)     schema/cyclonedx/1.2/bom-1.2.schema.json         https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.2.schema.json
SPDX v2.3.1 (development)     SPDX       SPDX-2.3  development  schema/spdx/2.3.1/spdx-schema.json               https://raw.githubusercontent.com/spdx/spdx-spec/development/v2.3.1/schemas/spdx-schema.json
SPDX v2.3                     SPDX       SPDX-2.3  (latest)     schema/spdx/2.3/spdx-schema.json                 https://raw.githubusercontent.com/spdx/spdx-spec/development/v2.3/schemas/spdx-schema.json
SPDX v2.2.2                   SPDX       SPDX-2.2  (latest)     schema/spdx/2.2.2/spdx-schema.json               https://raw.githubusercontent.com/spdx/spdx-spec/v2.2.2/schemas/spdx-schema.json
SPDX v2.2.1                   SPDX       SPDX-2.2  2.2.1        schema/spdx/2.2.1/spdx-schema.json               https://raw.githubusercontent.com/spdx/spdx-spec/v2.2.1/schemas/spdx-schema.json
```

#### Where flag (output filtering)

All `list` subcommands support the `--where`  flag. It can be used to filter output results based upon matches to regular expressions (regex) by using the output list's column titles as keys.

Multiple key-value (i.e., column-title=regex) pairs can be provided on the same `--where` filter flag using commas.

Syntax: `[--where key=regex[,...]]`

See each command's section for contextual examples of the `--where` flag filter usage.

---

### License

This command is used to aggregate and summarize software, hardware and data license information included in the SBOM. It also displays license usage policies for resources based upon concluded by SPDX license identifier, license family or logical license expressions as defined in he current policy file (i.e., `license.json`).

The `license` command supports the following subcommands:

- [list](#license-list-subcommand) - list or create a summarized report of licenses found in input SBOM.
  - [list with --summary flag](#license-list---summary-flag) - As full license information can be very large, a summary view is often most useful.
- [policy](#license-policy-subcommand) - list user configured license policies by SPDX license ID, family name and other filters.

---

### License `list` subcommand

The `list` subcommand produces JSON output which contains an array of CycloneDX `LicenseChoice` data objects found in the BOM input file without component association.  `LicenseChoice` data, in general, may provide license information using registered SPDX IDs, license expressions (of SPDX IDs) or license names (not necessarily registered by SPDX).  License data may also include base64-encoded license or legal text that was used to determine a license's SPDX ID or name.

#### License list supported formats

This command supports the `--format` flag with any of the following values:

- `json` (default), `csv`, `md`
  - using the `--summary` flag: `txt` (default), `csv`, `md`

#### License list result sorting

- Results are not sorted for base `license list` subcommand.
  - using the  `--summary` flag: results are sorted (ascending) by license key which can be one of license `id` (SPDX ID), `name` or `expression`.

#### License list flags

##### License list `--summary` flag

Use the `--summary` flag on the `license list` command to produce a summary report in `txt` (default) format as well as policy determination based upon the `license.json` declarations.

#### License list examples

##### Example: license list JSON

This example shows a few entries of the JSON output that exhibit the three types of license data described above:

```bash
./sbom-utility license list -i examples/cyclonedx/SBOM/juice-shop-11.1.2/bom.json --format json --quiet
```

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

###### Example: license list `--summary`

This example shows the default text output from using the summary flag:

```bash
./sbom-utility license list -i test/cyclonedx/cdx-1-3-license-list.json --summary --quiet
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

- **Notes**
  - **Usage policy** column values are derived from the `license.json` policy configuration file.
    - A `usage policy` value of `UNDEFINED` indicates that `license.json` provided no entry that matched the declared license (`id` or `name`) in the SBOM.
  - **License expressions** (e.g., `(MIT or GPL-2.0)`) with one term resolving to `UNDEFINED` and the the other term having a concrete policy will resolve to the "optimistic" policy for `OR` expressions and the "pessimistic" policy for `AND` expressions.  In addition, a warning of this resolution is emitted.

###### Example: license list summary with `--where` filter

The list command results can be filtered using the `--where` flag using the column names in the report. These include `usage-policy`, `license-type`, `license`, `resource-name`, `bom-ref` and `bom-location`.

The following example shows filtering of component licenses using the `license-type` column where the license was described as a `name` value:

```bash
./sbom-utility license list -i test/cyclonedx/cdx-1-3-license-list.json --summary --where license-type=name --quiet
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
./sbom-utility license list -i test/cyclonedx/cdx-1-3-license-list.json --summary --where usage-policy=needs-review --quiet
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

### License `policy` subcommand

To view a report listing the contents of the current policy file (i.e., [`license.json`](https://github.com/CycloneDX/sbom-utility/blob/main/license.json)) which contains an encoding of known software and data licenses by SPDX ID and license family along with a configurable usage policy (i.e., `"allow"`, `"deny"` or `"needs-review"`).

#### License policy supported formats

This command supports the `--format` flag with any of the following values:

- `txt` (default), `csv`, `md`

#### License policy result sorting

- Results are sorted by license policy `family`.

#### License policy flags

##### list `--summary` flag

Use the `--summary` flag on the `license policy list` command to produce a summary report with a reduced set of column data (i.e., it includes only the following columns:  `usage-policy`, `family`, `id`, `name`, `oci` (approved) `fsf` (approved), `deprecated`, and SPDX `reference` URL).

##### list `--wrap` flag

Use the `--wrap` flag to toggle the wrapping of text within columns of the license policy report (`txt` format only) output using the values `true` or `false`. The default value is `false`.

#### License policy examples

##### Example: license policy

```bash
./sbom-utility license policy --quiet
```

```bash
usage-policy  family    id            name                                osi    fsf    deprecated  reference                                    aliases                      annotations                  notes
------------  ------    --            ----                                ---    ---    ----------  ---------                                    -------                      -----------                  -----
allow         0BSD      0BSD          BSD Zero Clause License             true   false  false       https://spdx.org/licenses/0BSD.html          Free Public License 1.0.0    APPROVED                     none
needs-review  ADSL      ADSL          Amazon Digital Services License     false  false  false       https://spdx.org/licenses/ADSL.html          none                         NEEDS-APPROVAL               none
allow         AFL       AFL-3.0       Academic Free License v3.0          true   true   false       https://spdx.org/licenses/AFL-3.0.html       none                         APPROVED                     none
needs-review  AGPL      AGPL-1.0      Affero General Public License v1.0  false  false  true        https://spdx.org/licenses/AGPL-1.0.html      none                         NEEDS-APPROVAL,AGPL-WARNING  none
allow         Adobe     Adobe-2006    Adobe Systems Incorporated CLA      false  false  false       https://spdx.org/licenses/Adobe-2006.html    none                         APPROVED                     none
allow         Apache    Apache-2.0    Apache License 2.0                  true   true   false       https://spdx.org/licenses/Apache-2.0.html    Apache License, Version 2.0  APPROVED                     none
allow         Artistic  Artistic-1.0  Artistic License 1.0                true   false  false       https://spdx.org/licenses/Artistic-1.0.html  none                         APPROVED                     none
...
```

###### Example: policy with `--summary` flag

We can also apply the `--summary` flag to get a reduced set of columns that includes only the `usage-policy` along with the essential SPDX license information (e.g., no annotations or notes).

```bash
./sbom-utility license policy --summary --quiet
```

```bash
usage-policy  family    id            name                                osi     fsf     deprecated  reference
------------  ------    --            ----                                ---     ---     ----------  ---------
allow         0BSD      0BSD          BSD Zero Clause License             true    false   false       https://spdx.org/licenses/0BSD.html
needs-review  ADSL      ADSL          Amazon Digital Services License     false   false   false       https://spdx.org/licenses/ADSL.html
allow         AFL       AFL-3.0       Academic Free License v3.0          true    true    false       https://spdx.org/licenses/AFL-3.0.html
needs-review  AGPL      AGPL-1.0      Affero General Public License v1.0  false   false   true        https://spdx.org/licenses/AGPL-1.0.html
allow         Adobe     Adobe-2006    Adobe Systems Incorporated CLA      false   false   false       https://spdx.org/licenses/Adobe-2006.html
allow         Apache    Apache-2.0    Apache License 2.0                  true    true    false       https://spdx.org/licenses/Apache-2.0.html
allow         Artistic  Artistic-1.0  Artistic License 1.0                true    true    false       https://spdx.org/licenses/Artistic-2.0.html
...
```

###### Example: policy with `--where` filter

The following example shows filtering of  license policies using the `id` column:

```bash
./sbom-utility license policy --where id=Apache
```

```bash
usage-policy  family  id          name                osi     fsf     deprecated  reference                                  aliases         annotations  notes
------------  ------  --          ----                ---     ---     ----------  ---------                                  -------         -----------  -----
allow         Apache  Apache-1.0  Apache v1.0         false   true    false       https://spdx.org/licenses/Apache-1.0.html  none            APPROVED     none
allow         Apache  Apache-1.1  Apache v1.1         true    true    false       https://spdx.org/licenses/Apache-1.1.html  none            APPROVED     Superseded by Apache-2.0
allow         Apache  Apache-2.0  Apache License 2.0  true    true    false       https://spdx.org/licenses/Apache-2.0.html  Apache License  APPROVED     none

```

###### Example: policy with `--wrap` flag

```bash
./sbom-utility license policy --quiet --wrap=true
```

```bash
usage-policy  family    id             name                          osi     fsf     deprecated  reference                                     aliases                           annotations             notes
------------  ------    --             ----                          ---     ---     ----------  ---------                                     -------                           -----------             -----
allow         0BSD      0BSD           BSD Zero Clause Lice (20/23)  true    false   false       https://spdx.org/licenses/0BSD.html           Free Public License 1.0. (24/25)  APPROVED                none
needs-review  ADSL      ADSL           Amazon Digital Servi (20/31)  false   false   false       https://spdx.org/licenses/ADSL.html                                             NEEDS-APPROVAL          none
allow         AFL       AFL-3.0        Academic Free Licens (20/26)  true    true    false       https://spdx.org/licenses/AFL-3.0.ht (36/38)                                    APPROVED                none
needs-review  AGPL      AGPL-1.0       Affero General Publi (20/34)  false   false   true        https://spdx.org/licenses/AGPL-1.0.h (36/39)                                    NEEDS-APPROVAL          none
                                                                                                                                                                                 AGPL-WARNING
needs-review  APSL      APSL-2.0       Apple Public Source  (20/31)  true    true    false       https://spdx.org/licenses/APSL-2.0.h (36/39)                                    NEEDS-APPROVAL          none
allow         Adobe     Adobe-2006     Adobe Systems Incorp (20/56)  false   false   false       https://spdx.org/licenses/Adobe-2006 (36/41)                                    APPROVED                none
allow         Apache    Apache-2.0     Apache License 2.0            true    true    false       https://spdx.org/licenses/Apache-2.0 (36/41)  Apache License, Version  (24/27)  APPROVED                none
allow         Artistic  Artistic-2.0   Artistic License 2.0          true    true    false       https://spdx.org/licenses/Artistic-2 (36/43)                                    APPROVED                none
...
```

#### License policy notes

- Currently, the default `license.json` file, used to derive the `usage-policy` data, does not contain entries for the entire set of SPDX 3.2 license templates.
  - An issue [12](https://github.com/CycloneDX/sbom-utility/issues/12) is open to add parity.
- Annotations (tags) and notes can be defined within the `license.json` file and one or more assigned each license entry.
<!-- - Column data is, by default, truncated in `txt` format views only. In these cases, the number of characters shown out of the total available will be displayed at the point of truncation (e.g., seeing `(24/26)` in a column would indicate 24 out of 26 characters were displayed). -->
- For backwards compatibility, the `--where` filter supports the key `spdx-id` as an alias for `id`.

---

### Query

This command allows you to perform SQL-like queries into JSON format SBOMs.  Currently, the command recognizes the `--select` and `--from` as well as the `--where` filter.

#### Query flags

##### Query `--from` flag

The `--from` clause value is applied to the JSON document object model and can return either a singleton JSON object or an array of JSON objects as a result.  This is determined by the last property value's type as declared in the schema.

##### Query `--select` flag

The `--select` clause is then applied to the `--from` result set to only return the specified properties (names and their values).

##### Query `--where` flag

If the result set is an array, the array entries can be reduced by applying the `--where` filter to ony return those entries whose specified field names match the supplied regular expression (regex).

**Note**: All `query` command results are returned as valid JSON documents.  This includes a `null` value for empty result sets.

#### Query supported formats

The `query` command only supports JSON output.

- `json` (default)

#### Query result sorting

The `query` command does not support formatting of output results as JSON format is always returned.

#### Query examples

##### Example: Extract the top-level `component` information from an SBOM

This example effectively extracts the first-order package manifest from the SBOM.

In this example, only the `--from` clause is needed to select an object.  The `--select` clause is omitted which is equivalent to using the "select all" wildcard character `*` which returns all fields and values from the `component` object.

```bash
./sbom-utility query -i test/cyclonedx/cdx-1-4-mature-example-1.json --from metadata.component
```

is equivalent to using the wildcard character (which may need to be enclosed in single or double quotes depending on your shell):

```bash
./sbom-utility query -i test/cyclonedx/cdx-1-4-mature-example-1.json --select '*' --from metadata.component --quiet
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

##### Example: Extract the `supplier` of the SBOM

In this example, the `--from` clause references the top-level `metadata.supplier` object.

```bash
./sbom-utility query -i test/cyclonedx/cdx-1-4-mature-example-1.json --from metadata.supplier --quiet
```

```json
{
  "contact": [
    {
      "email": "distribution@example.com"
    }
  ],
  "name": "Example Co. Distribution Dept.",
  "url": [
    "https://example.com/software/"
  ]
}
```

##### Example: Extract just the SBOM component's `name` and `version`

In this example, the `--from` clause references the singleton JSON object `component` found under the top-level `metadata` object. It then reduces the resultant JSON object to only return the `name` and `value` fields and their values as requested on the `--select` clause.

```bash
./sbom-utility query --select name,version --from metadata.component -i examples/cyclonedx/SBOM/juice-shop-11.1.2/bom.json --quiet
```

```json
{
  "name": "juice-shop",
  "version": "11.1.2"
}
```

##### Example: Return the JSON array of components

In this example, the `--from` filter will return the entire JSON components array.

```bash
./sbom-utility query -i test/cyclonedx/cdx-1-4-mature-example-1.json --from components --quiet
```

```json
[
  {
    "bom-ref": "pkg:npm/sample@2.0.0",
    "description": "Node.js Sampler package",
    "licenses": [
      {
        "license": {
          "id": "MIT"
        }
      }
    ],
    "name": "sample",
    "purl": "pkg:npm/sample@2.0.0",
    "type": "library",
    "version": "2.0.0"
  },
  {
    "bom-ref": "pkg:npm/body-parser@1.19.0",
    "description": "Node.js body parsing middleware",
    "hashes": [
      {
        ...
      }
    ],
    "licenses": [
      {
        "license": {
          "id": "MIT"
        }
      }
    ],
    "name": "body-parser",
    "purl": "pkg:npm/body-parser@1.19.0",
    "type": "library",
    "version": "1.19.0"
  }
]
```

**Note**: The command for this example only used the `--from` flag and did not need to supply `--select '*'` as this us the default.

##### Example: Filter result entries with a specified value

In this example, the `--where` filter will be applied to a set of `properties` results to only include entries that match the specified regex.

```bash
./sbom-utility query -i test/cyclonedx/cdx-1-4-mature-example-1.json --from metadata.properties --where name=urn:example.com:classification --quiet
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
./sbom-utility query -i test/cyclonedx/cdx-1-4-mature-example-1.json --select value --from metadata.properties --where name=urn:example.com:classification --quiet
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

#### Resource supported output formats

This command supports the `--format` flag with any of the following values:

- `txt` (default), `csv`, `md`

#### Resource result sorting

Currently, all `resource list` command results are sorted by resource `type` then by resource `name` (required field).

#### Resource Examples

#### Example: resource list

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

##### Example: resource list using `--type service`

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

##### Example: list with `name` regex match

This example uses the `where` filter on the `name` field. In this case we supply an exact "startswith" regex. for the `name` filter.

```bash
./sbom-utility resource list -i test/cyclonedx/cdx-1-3-resource-list.json --where "name=Library A" --quiet
```

```bash
type       name       version  bom-ref
----       ----       -------  -------
component  Library A  1.0.0    pkg:lib/libraryA@1.0.0
```

---

### Schema

You can verify which formats, schemas, versions and variants are available for validation by using the `schema` command:

```bash
./sbom-utility schema list
```

- **Note**: The `schema` command will default to the `list` subcommand if omitted.

#### Schema supported output formats

This command supports the `--format` flag with any of the following values:

- `txt` (default), `csv`, `md`

#### Schema result sorting

- Formatted results are sorted by `format` (ascending), `version` (descending) and `schema` (descending)

#### Schema examples

##### Example: schema list

```bash
name            variant      format     version   file                                             url
----            -------      ------     -------   ----                                             ---
CycloneDX v1.6  development  CycloneDX  1.6       schema/cyclonedx/1.6/bom-1.6.schema.json         https://raw.githubusercontent.com/CycloneDX/specification/1.6-dev/schema/bom-1.6.schema.json
CycloneDX v1.5  (latest)     CycloneDX  1.5       schema/cyclonedx/1.5/bom-1.5.schema.json         https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.5.schema.json
CycloneDX v1.4  (latest)     CycloneDX  1.4       schema/cyclonedx/1.4/bom-1.4.schema.json         https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.4.schema.json
CycloneDX v1.4  custom       CycloneDX  1.4       schema/test/bom-1.4-custom.schema.json
CycloneDX v1.3  (latest)     CycloneDX  1.3       schema/cyclonedx/1.3/bom-1.3.schema.json         https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.3.schema.json
CycloneDX v1.3  custom       CycloneDX  1.3       schema/test/bom-1.3-custom.schema.json
CycloneDX v1.3  strict       CycloneDX  1.3       schema/cyclonedx/1.3/bom-1.3-strict.schema.json  https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.3-strict.schema.json
CycloneDX v1.2  (latest)     CycloneDX  1.2       schema/cyclonedx/1.2/bom-1.2.schema.json         https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.2.schema.json
CycloneDX v1.2  strict       CycloneDX  1.2       schema/cyclonedx/1.2/bom-1.2-strict.schema.json  https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.2-strict.schema.json
SPDX v2.3       (latest)     SPDX       SPDX-2.3  schema/spdx/2.3/spdx-schema.json                 https://raw.githubusercontent.com/spdx/spdx-spec/development/v2.3/schemas/spdx-schema.json
SPDX v2.3.1     development  SPDX       SPDX-2.3  schema/spdx/2.3.1/spdx-schema.json               https://raw.githubusercontent.com/spdx/spdx-spec/development/v2.3.1/schemas/spdx-schema.json
SPDX v2.2.2     (latest)     SPDX       SPDX-2.2  schema/spdx/2.2.2/spdx-schema.json               https://raw.githubusercontent.com/spdx/spdx-spec/v2.2.2/schemas/spdx-schema.json
SPDX v2.2.1     2.2.1        SPDX       SPDX-2.2  schema/spdx/2.2.1/spdx-schema.json               https://raw.githubusercontent.com/spdx/spdx-spec/v2.2.1/schemas/spdx-schema.json
```

#### Adding schemas

Entries for new or "custom" schemas can be added to the `config.json` file by adding a new schema entry and then will need to pass that file on the command line using the `--config-schema` flag.

These new schema entries will tell the schema loader where to find the JSON schema file locally, relative to the utility's executable.

For details see the "[Adding SBOM formats, schema versions and variants](#adding-sbom-formats-schema-versions-and-variants)" section.

#### Embedding schemas

If you wish to have the new schema *embedded in the executable*, simply add it to the project's `resources` subdirectory following the format and version-based directory structure.

---

### Trim

This command is able to "trim" one or more JSON keys (fields) from specified JSON BOM documents effectively "pruning" the JSON document.  This functionality helps consumers of large-sized BOMs that need to analyze specific types of data in large BOMs in reducing the BOM data to just what is needed for their use cases or needs.

#### Trim supported output formats

This command is used to output, using the [`--output-file` flag](#output-flag), a "trimmed" BOM in JSON format.

- `json` (default)

#### Trim flags

Trim operates on a JSON BOM input file (see [`--input-file` flag](#input-flag)) and produces a trimmed JSON BOM output file using the following flags:

##### Trim `--keys` flag

A comma-separated list of JSON map keys. Similar to the [query command's `--select` flag](#query---select-flag) syntax.

##### Trim `--from` flag

A comma-separated list of JSON document paths using the same syntax as the [query command's `--from` flag](#query---from-flag).

#### Trim examples

The original BOM used for these examples can be found here:

- [test/trim/trim-cdx-1-5-sample-small-components-only.sbom.json](test/trim/trim-cdx-1-5-sample-small-components-only.sbom.json)

##### Example: Trim `properties` from entire JSON BOM

Validating the "juice shop" SBOM (CycloneDX 1.2) example provided in this repository.

```bash
./sbom-utility trim -i ./sbom-utility trim -i test/trim/trim-cdx-1-5-sample-small-components-only.sbom.json --keys=properties
```

Original BOM with properties:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "serialNumber": "urn:uuid:1a2b3c4d-1234-abcd-9876-a3b4c5d6e7f9",
  "components": [
    {
      "type": "library",
      "bom-ref": "pkg:npm/sample@2.0.0",
      "purl": "pkg:npm/sample@2.0.0",
      "name": "sample",
      "version": "2.0.0",
      "description": "Node.js Sampler package",
      "properties": [
        {
          "name": "foo",
          "value": "bar"
        }
      ]
    },
    {
      "type": "library",
      "bom-ref": "pkg:npm/body-parser@1.19.0",
      "purl": "pkg:npm/body-parser@1.19.0",
      "name": "body-parser",
      "version": "1.19.0",
      "description": "Node.js body parsing middleware",
      "hashes": [
        {
          "alg": "SHA-1",
          "content": "96b2709e57c9c4e09a6fd66a8fd979844f69f08a"
        }
      ]
    }
  ],
  "properties": [
    {
      "name": "abc",
      "value": "123"
    }
  ]
}
```

Output BOM results without `properties``:

```json
{
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": "urn:uuid:1a2b3c4d-1234-abcd-9876-a3b4c5d6e7f9",
    "version": 1,
    "components": [
        {
            "type": "library",
            "bom-ref": "pkg:npm/sample@2.0.0",
            "name": "sample",
            "version": "2.0.0",
            "description": "Node.js Sampler package",
            "purl": "pkg:npm/sample@2.0.0"
        },
        {
            "type": "library",
            "bom-ref": "pkg:npm/body-parser@1.19.0",
            "name": "body-parser",
            "version": "1.19.0",
            "description": "Node.js body parsing middleware",
            "hashes": [
                {
                    "alg": "SHA-1",
                    "content": "96b2709e57c9c4e09a6fd66a8fd979844f69f08a"
                }
            ],
            "purl": "pkg:npm/body-parser@1.19.0"
        }
    ]
}
```

##### Example: Trim `name` and `description` from entire JSON BOM

```bash
./sbom-utility trim -i test/trim/trim-cdx-1-5-sample-small-components-only.sbom.json --keys=name,description --quiet
```

Output BOM results without `name` or `description`:

```json
{
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": "urn:uuid:1a2b3c4d-1234-abcd-9876-a3b4c5d6e7f9",
    "version": 1,
    "components": [
        {
            "type": "library",
            "bom-ref": "pkg:npm/sample@2.0.0",
            "version": "2.0.0",
            "purl": "pkg:npm/sample@2.0.0",
            "properties": [
                {
                    "value": "bar"
                }
            ]
        },
        {
            "type": "library",
            "bom-ref": "pkg:npm/body-parser@1.19.0",
            "version": "1.19.0",
            "hashes": [
                {
                    "alg": "SHA-1",
                    "content": "96b2709e57c9c4e09a6fd66a8fd979844f69f08a"
                }
            ],
            "purl": "pkg:npm/body-parser@1.19.0"
        }
    ],
    "properties": [
        {
            "value": "123"
        }
    ]
}
```

##### Example: Trim `properties` from only `components` path

```bash
./sbom-utility trim -i test/trim/trim-cdx-1-5-sample-small-components-only.sbom.json --keys=properties --from components --quiet
```

Output BOM results with `properties` removed from all `components`:

```json
{
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": "urn:uuid:1a2b3c4d-1234-abcd-9876-a3b4c5d6e7f9",
    "version": 1,
    "components": [
        {
            "type": "library",
            "bom-ref": "pkg:npm/sample@2.0.0",
            "name": "sample",
            "version": "2.0.0",
            "description": "Node.js Sampler package",
            "purl": "pkg:npm/sample@2.0.0"
        },
        {
            "type": "library",
            "bom-ref": "pkg:npm/body-parser@1.19.0",
            "name": "body-parser",
            "version": "1.19.0",
            "description": "Node.js body parsing middleware",
            "hashes": [
                {
                    "alg": "SHA-1",
                    "content": "96b2709e57c9c4e09a6fd66a8fd979844f69f08a"
                }
            ],
            "purl": "pkg:npm/body-parser@1.19.0"
        }
    ],
    "properties": [
        {
            "name": "abc",
            "value": "123"
        }
    ]
}
```

---

### Validate

This command will parse standardized SBOMs and validate it against its declared format and version (e.g., SPDX 2.2, CycloneDX 1.4). Custom  variants of standard JSON schemas can be used for validation by supplying the `--variant` name as a flag. Explicit JSON schemas can be specified using the `--force` flag.

#### Validate supported schemas

Use the [schema](#schema) command to list supported schemas formats, versions and variants.

Customized JSON schemas can also be permanently configured as named schema "variants" within the utility's configuration file. See [adding schemas](#adding-schemas).

#### Validate flags

The following flags can be used to improve performance when formatting error output results:

##### `--error-limit` flag

Use the `--error-limit x` (default: `10`) flag to reduce the formatted error result output to the first `x` errors.  By default, only the first 10 errors are output with an informational messaging indicating `x/y` errors were shown.

##### `--error-value` flag

Use the `--error-value=true|false` (default: `true`) flag to reduce the formatted error result output by not showing the `value` field which shows detailed information about the failing data in the BOM.

##### `--colorize` flag

Use the `--colorize=true|false` (default: `false`) flag to add/remove color formatting to error result `txt` formatted output.  By default, `txt` formatted error output is colorized to help with human readability; for automated use, it can be turned off.

#### Validate Examples

##### Example: Validate using inferred format and schema

Validating the "juice shop" SBOM (CycloneDX 1.2) example provided in this repository.

```bash
./sbom-utility validate -i examples/cyclonedx/SBOM/juice-shop-11.1.2/bom.json
```

```bash
[INFO] Loading (embedded) default schema config file: `config.json`...
[INFO] Loading (embedded) default license policy file: `license.json`...
[INFO] Attempting to load and unmarshal data from: `examples/cyclonedx/SBOM/juice-shop-11.1.2/bom.json`...
[INFO] Successfully unmarshalled data from: `examples/cyclonedx/SBOM/juice-shop-11.1.2/bom.json`
[INFO] Determining file's BOM format and version...
[INFO] Determined BOM format, version (variant): `CycloneDX`, `1.2` (latest)
[INFO] Matching BOM schema (for validation): schema/cyclonedx/1.2/bom-1.2.schema.json
[INFO] Loading schema `schema/cyclonedx/1.2/bom-1.2.schema.json`...
[INFO] Schema `schema/cyclonedx/1.2/bom-1.2.schema.json` loaded.
[INFO] Validating `examples/cyclonedx/SBOM/juice-shop-11.1.2/bom.json`...
[INFO] BOM valid against JSON schema: `true`
```

You can also verify the [exit code](#exit-codes) from the validate command:

```bash
echo $?
```

```bash
0  // no error (valid)
```

#### Example: Validate using "custom" schema variants

The validation command will use the declared format and version found within the SBOM JSON file itself to lookup the default (latest) matching schema version (as declared in`config.json`; however, if variants of that same schema (same format and version) are declared, they can be requested via the `--variant` command line flag:

```bash
./sbom-utility validate -i test/custom/cdx-1-4-test-custom-metadata-property-disclaimer-invalid.json --variant custom
```

If you run the sample command above, you would see several "custom" schema errors resulting in an invalid SBOM determination (i.e., `exit status 2`):

```text
[INFO] Loading (embedded) default schema config file: `config.json`...
[INFO] Loading (embedded) default license policy file: `license.json`...
[INFO] Attempting to load and unmarshal data from: `test/custom/cdx-1-4-test-custom-metadata-property-disclaimer-invalid.json`...
[INFO] Successfully unmarshalled data from: `test/custom/cdx-1-4-test-custom-metadata-property-disclaimer-invalid.json`
[INFO] Determining file's BOM format and version...
[INFO] Determined BOM format, version (variant): `CycloneDX`, `1.4` custom
[INFO] Matching BOM schema (for validation): schema/test/bom-1.4-custom.schema.json
[INFO] Loading schema `schema/test/bom-1.4-custom.schema.json`...
[INFO] Schema `schema/test/bom-1.4-custom.schema.json` loaded.
[INFO] Validating `test/custom/cdx-1-4-test-custom-metadata-property-disclaimer-invalid.json`...
[INFO] BOM valid against JSON schema: `false`
[INFO] (3) schema errors detected.
[INFO] Formatting error results (`txt` format)...
1. {
        "type": "contains",
        "field": "metadata.properties",
        "context": "(root).metadata.properties",
        "description": "At least one of the items must match",
        "value": [
            {
                "name": "urn:example.com:disclaimer",
                "value": "This SBOM is current as of the date it was generated."
            },
            {
                "name": "urn:example.com:classification",
                "value": "This SBOM is Confidential Information. Do not distribute."
            }
        ]
    }
2. {
        "type": "const",
        "field": "metadata.properties.0.value",
        "context": "(root).metadata.properties.0.value",
        "description": "metadata.properties.0.value does not match: \"This SBOM is current as of the date it was generated and is subject to change.\"",
        "value": "This SBOM is current as of the date it was generated."
    }
3. {
        "type": "number_all_of",
        "field": "metadata.properties",
        "context": "(root).metadata.properties",
        "description": "Must validate all the schemas (allOf)",
        "value": [
            {
                "name": "urn:example.com:disclaimer",
                "value": "This SBOM is current as of the date it was generated."
            },
            {
                "name": "urn:example.com:classification",
                "value": "This SBOM is Confidential Information. Do not distribute."
            }
        ]
    }
[ERROR] invalid SBOM: schema errors found (test/custom/cdx-1-4-test-custom-metadata-property-disclaimer-invalid.json)
[INFO] document `test/custom/cdx-1-4-test-custom-metadata-property-disclaimer-invalid.json`: valid=[false]
```

confirming the exit code:

```bash
echo $?
```

```bash
2 // SBOM error
```

##### Why validation failed

The output shows a first schema error indicating the failing JSON object; in this case,

- the CycloneDX `metadata.properties` field, which is a list of `property` objects.
- Found that a property with a `name` field with the value  `"urn:example.com:disclaimer"` had an incorrect `value`.
  - the `value` field SHOULD have had a constant value of `"This SBOM is current as of the date it was generated and is subject to change."` (as was required by the custom schema's regex).
  - However, it was found to have only a partial match of `"This SBOM is current as of the date it was generated."`.

##### Details of the schema error

Use the `--debug` or `-d` flag to see all schema error details:

```bash
./sbom-utility validate -i test/custom/cdx-1-4-test-custom-metadata-property-disclaimer-invalid.json --variant custom -d
```

The details include the full context of the failing `metadata.properties` object which also includes a `"urn:example.com:classification"` property:

```bash
3. {
        "type": "number_all_of",
        "field": "metadata.properties",
        "context": "(root).metadata.properties",
        "description": "Must validate all the schemas (allOf)",
        "value": [
            {
                "name": "urn:example.com:disclaimer",
                "value": "This SBOM is current as of the date it was generated."
            },
            {
                "name": "urn:example.com:classification",
                "value": "This SBOM is Confidential Information. Do not distribute."
            }
        ]
    }
```

#### Example: Validate using "JSON" format

The JSON format will provide an `array` of schema error results that can be post-processed as part of validation toolchain.

```bash
./sbom-utility validate -i test/validation/cdx-1-4-validate-err-components-unique-items-1.json --format json --quiet
```

```json
[
    {
        "type": "unique",
        "field": "components",
        "context": "(root).components",
        "description": "array items[1,2] must be unique",
        "value": {
            "type": "array",
            "index": 1,
            "item": {
                "bom-ref": "pkg:npm/body-parser@1.19.0",
                "description": "Node.js body parsing middleware",
                "hashes": [
                    {
                        "alg": "SHA-1",
                        "content": "96b2709e57c9c4e09a6fd66a8fd979844f69f08a"
                    }
                ],
                "licenses": [
                    {
                        "license": {
                            "id": "MIT"
                        }
                    }
                ],
                "name": "body-parser",
                "purl": "pkg:npm/body-parser@1.19.0",
                "type": "library",
                "version": "1.19.0"
            }
        }
    },
    {
        "type": "unique",
        "field": "components",
        "context": "(root).components",
        "description": "array items[2,4] must be unique",
        "value": {
            "type": "array",
            "index": 2,
            "item": {
                "bom-ref": "pkg:npm/body-parser@1.19.0",
                "description": "Node.js body parsing middleware",
                "hashes": [
                    {
                        "alg": "SHA-1",
                        "content": "96b2709e57c9c4e09a6fd66a8fd979844f69f08a"
                    }
                ],
                "licenses": [
                    {
                        "license": {
                            "id": "MIT"
                        }
                    }
                ],
                "name": "body-parser",
                "purl": "pkg:npm/body-parser@1.19.0",
                "type": "library",
                "version": "1.19.0"
            }
        }
    }
]
```

##### Reducing output size using `error-value=false` flag

In many cases, BOMs may have many errors and having the `value` information details included can be too verbose and lead to large output files to inspect.  In those cases, simply set the `error-value` flag to `false`.

Rerunning the same command with this flag set to false yields a reduced set of information.

```bash
./sbom-utility validate -i test/validation/cdx-1-4-validate-err-components-unique-items-1.json --format json --error-value=false --quiet
```

```json
[
    {
        "type": "unique",
        "field": "components",
        "context": "(root).components",
        "description": "array items[1,2] must be unique"
    },
    {
        "type": "unique",
        "field": "components",
        "context": "(root).components",
        "description": "array items[2,4] must be unique"
    }
]
```

---

### Vulnerability

This command will extract basic vulnerability report data from an SBOM that has a "vulnerabilities" list or from a standalone VEX in CycloneDX format. It includes the ability to filter reports data by applying regex to any of the named column data.

#### Vulnerability supported output formats

Use the `--format` flag on the to choose one of the supported output formats:

- txt (default), csv, md

#### Vulnerability result sorting

- `txt`, `csv` and `md` formatted results are sorted by vulnerability `id` (descending) then by `created` date (descending).
- `json` results are not sorted

#### Vulnerability Examples

##### Example: Vulnerability list

The `list` subcommand provides a complete view of most top-level, vulnerability fields.

```bash
./sbom-utility vulnerability list -i test/vex/cdx-1-3-example1-bom-vex.json --quiet
```

```bash
id              bom-ref  cwe-ids  cvss-severity                                                source-name  source-url                                       published   updated     created     rejected  analysis-state  analysis-justification  description
--              -------  -------  -------------                                                -----------  ----------                                       ---------   -------     -------     --------  --------------  ----------------------  -----------
CVE-2023-42004           502      CVSSv31: 7.5 (high)                                          NVD          https://nvd.nist.gov/vuln/detail/CVE-2023-42004  2023-10-02  2023-10-02  2023-10-02            UNDEFINED       UNDEFINED               In FasterXML jackson-databind before 2.13.4, resource exhaustion can occur because of a lack of a check in BeanDeserializer._deserializeFromArray to prevent use of deeply nested arrays. An application is vulnerable only with certain customized choices for deserialization.
CVE-2023-42003           502      CVSSv31: 7.5 (high)                                          NVD          https://nvd.nist.gov/vuln/detail/CVE-2023-42003  2023-10-02  2023-10-02  2023-10-02            UNDEFINED       UNDEFINED               In FasterXML jackson-databind before 2.14.0-rc1, resource exhaustion can occur because of a lack of a check in primitive value deserializers to avoid deep wrapper array nesting, when the UNWRAP_SINGLE_VALUE_ARRAYS feature is enabled. Additional fix version in 2.13.4.1 and 2.12.17.1
CVE-2020-25649           611      CVSSv31: 7.5 (high), CVSSv31: 8.2 (high), CVSSv31: 0 (none)  NVD          https://nvd.nist.gov/vuln/detail/CVE-2020-25649  2020-12-03  2023-02-02  2020-12-03            not_affected    code_not_reachable      com.fasterxml.jackson.core:jackson-databind is a library which contains the general-purpose data-binding functionality and tree-model for Jackson Data Processor.  Affected versions of this package are vulnerable to XML External Entity (XXE) Injection. A flaw was found in FasterXML Jackson Databind, where it does not have entity expansion secured properly in the DOMDeserializer class. The highest threat from this vulnerability is data integrity.
```

###### Example: Vulnerability list summary

This example shows the default text output from using the `--summary` flag:

```bash
./sbom-utility vulnerability list -i test/vex/cdx-1-3-example1-bom-vex.json --quiet --summary
```

```bash
id              cvss-severity        source-name  published   description
--              -------------        -----------  ---------   -----------
CVE-2023-42004  CVSSv31: 7.5 (high)  NVD          2023-10-02  In FasterXML jackson-databind before 2.13.4, resource exhaustion can occur because of a lack of a check in BeanDeserializer._deserializeFromArray to prevent use of deeply nested arrays. An application is vulnerable only with certain customized choices for deserialization.
CVE-2023-42003  CVSSv31: 7.5 (high)  NVD          2023-10-02  In FasterXML jackson-databind before 2.14.0-rc1, resource exhaustion can occur because of a lack of a check in primitive value deserializers to avoid deep wrapper array nesting, when the UNWRAP_SINGLE_VALUE_ARRAYS feature is enabled. Additional fix version in 2.13.4.1 and 2.12.17.1
CVE-2020-25649  CVSSv31: 7.5 (high)  NVD          2020-12-03  com.fasterxml.jackson.core:jackson-databind is a library which contains the general-purpose data-binding functionality and tree-model for Jackson Data Processor.  Affected versions of this package are vulnerable to XML External Entity (XXE) Injection. A flaw was found in FasterXML Jackson Databind, where it does not have entity expansion secured properly in the DOMDeserializer class. The highest threat from this vulnerability is data integrity.
```

##### Example: Vulnerability list with `--where` filter with `description` key

```bash
./sbom-utility vulnerability list -i test/vex/cdx-1-3-example1-bom-vex.json --quiet --where description=XXE
```

```bash
id              bom-ref  cwe-ids  cvss-severity                                                source-name  source-url                                       published   updated     created     rejected  analysis-state  analysis-justification  description
--              -------  -------  -------------                                                -----------  ----------                                       ---------   -------     -------     --------  --------------  ----------------------  -----------
CVE-2020-25649           611      CVSSv31: 7.5 (high), CVSSv31: 8.2 (high), CVSSv31: 0 (none)  NVD          https://nvd.nist.gov/vuln/detail/CVE-2020-25649  2020-12-03  2023-02-02  2020-12-03            not_affected    code_not_reachable      com.fasterxml.jackson.core:jackson-databind is a library which contains the general-purpose data-binding functionality and tree-model for Jackson Data Processor.  Affected versions of this package are vulnerable to XML External Entity (XXE) Injection. A flaw was found in FasterXML Jackson Databind, where it does not have entity expansion secured properly in the DOMDeserializer class. The highest threat from this vulnerability is data integrity.
```

##### Example: Vulnerability list with `--where` filter with `analysis-state` key

```bash
./sbom-utility vulnerability list -i test/vex/cdx-1-3-example1-bom-vex.json --quiet --where analysis-state=not_affected
```

```bash
id              bom-ref  cwe-ids  cvss-severity                                                source-name  source-url                                       published   updated     created     rejected  analysis-state  analysis-justification  description
--              -------  -------  -------------                                                -----------  ----------                                       ---------   -------     -------     --------  --------------  ----------------------  -----------
CVE-2020-25649           611      CVSSv31: 7.5 (high), CVSSv31: 8.2 (high), CVSSv31: 0 (none)  NVD          https://nvd.nist.gov/vuln/detail/CVE-2020-25649  2020-12-03  2023-02-02  2020-12-03            not_affected    code_not_reachable      com.fasterxml.jackson.core:jackson-databind is a library which contains the general-purpose data-binding functionality and tree-model for Jackson Data Processor.  Affected versions of this package are vulnerable to XML External Entity (XXE) Injection. A flaw was found in FasterXML Jackson Databind, where it does not have entity expansion secured properly in the DOMDeserializer class. The highest threat from this vulnerability is data integrity.
```

---

#### Completion

This command will generate command-line completion scripts, for the this utility, customized for various supported shells.

The completion command can be invoked as follows:

```bash
./sbom_utility completion [shell]
```

where valid values for `shell` are:

- bash
- fish
- powershell
- zsh

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

## Experimental Commands

This section contains *experimental* commands that will be promoted once vetted by the community over two or more point releases.

### Diff

This *experimental* command will compare two *similar* BOMs and return the delta (or "diff") in JSON (diff-patch format) or text. This functionality is based upon code ancestral to that used to report file diffs between `git commit`s.

##### Notes

- This command is undergoing analysis and tests which are exposing some underlying issues around "moved" objects in dependent diff-patch packages that may not be fixable and have no alternatives.
  - *Specifically, the means by which "moved" objects are assigned "similarity" scores appears flawed in the case of JSON.*
  - *Additionally, some of the underlying code relies upon Go maps which do not preserve key ordering.*

#### Diff supported output formats

Use the `--format` flag on the to choose one of the supported output formats:

- txt (default), json

#### Diff Examples

##### Example: Add, delete and modify

```bash
./sbom-utility diff -i test/diff/json-array-order-change-with-add-and-delete-base.json -r test/diff/json-array-order-change-with-add-and-delete-delta.json --quiet --format txt --colorize=true
```

```bash
 {
   "licenses": [
     0: {
       "license": {
-        "id": "Apache-1.0"
+        "id": "GPL-2.0"
       }
     },
-+    2=>1: {
-+      "license": {
-+        "id": "GPL-3.0-only"
-+      }
-+    },
     2: {
       "license": {
         "id": "GPL-3.0-only"
       }
     },
     3: {
       "license": {
         "id": "MIT"
       }
     }
   ]
 }
```

---

### Patch

This *experimental* command is able to "patch" an existing JSON BOM document using an [IETF RFC6902](https://datatracker.ietf.org/doc/html/rfc6902/#section-4.1) *"JavaScript Object Notation (JSON) Patch"* file.

The current implementation supports the following "patch" operations:

- "add", "update", "remove" and "test"

At this time the "move" or "copy" operations are not supported.

Patches work for both simple (i.e., integer, float, boolean and string) values as well as complex values such as JSON objects, maps and arrays.

#### Patch supported output formats

This command is used to output, using the [`--output-file` flag](#output-flag), a "patched" BOM in JSON format.

- `json` (default)

#### Patch flags

The patch command operates on a JSON BOM input file (see [`--input-file` flag](#input-flag)) as well as an [IETF RFC6902](https://datatracker.ietf.org/doc/html/rfc6902/#section-4.1)-formatted "patch' file and produces a "patched" version of the input JSON BOM as output using the following flags:

##### Patch `--patch-filename` flag

The `--patch-file <filename>` flag is used to provide the relative path to the IETF RFC6902 patch file to applied to the BOM input file.

#### Patch examples

This section contains examples of all supported patch operations (i.e., add, replace, test) including values that are primitives (i.e., `numbers`, `strings`) as well as JSON `objects` and may be indexed JSON `array` elements.

- ["add" BOM `serialNumber`](#patch-example-1-add-bom-serialnumber)
- ["add" (update) BOM `version`](#patch-example-2-add-update-bom-version)
- ["add" `supplier` object to `metadata`](#patch-example-3-add-supplier-object-to-metadata-object)
- ["add" `property` objects to `metadata.properties` array](#patch-example-4-add-property-objects-to-metadataproperties-array)
- ["replace" `version` and `timestamp` values](#patch-example-5-replace-bom-version-and-timestamp)
- ["remove" `property` from the `metadata.properties` array](#patch-example-6-remove-property-from-the-metadataproperties-array)
- ["test" if a `property` exists in the `metadata.properties` array](#patch-example-7-test-property-exists-in-the-metadataproperties-array)

##### Patch example 1: "add" BOM `serialNumber`

This example adds a new top-level key `"serialNumber"` and corresponding value to a CycloneDX JSON BOM file.

The original CycloneDX JSON BOM file: [test/patch/cdx-1-5-simplest-base.json](test/patch/cdx-1-5-simplest-base.json) has no serial number:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
      ...
  }
}
```

IETF RFC6902 JSON Patch file: [test/patch/cdx-patch-example-add-serial-number.json](test/patch/cdx-patch-example-add-serial-number.json):

```json
[
  { "op": "add", "path": "/serialNumber", "value": "urn:uuid:1a2b3c4d-1234-abcd-9876-a3b4c5d6e7f9" }
]
```

Invoke the patch command as follows:

```bash
./sbom-utility patch --input-file test/patch/cdx-1-5-simplest-base.json --patch-file test/patch/cdx-patch-example-add-serial-number.json  -q
```

Patched JSON BOM output file:

```json
{
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": "urn:uuid:1a2b3c4d-1234-abcd-9876-a3b4c5d6e7f9",
    "version": 1,
    "metadata": {
        ...
    }
}
```

##### Patch example 2: "add" (update) BOM `version`

This example shows how the patch's "add" operation can be used to update existing values which is the specified behavior of RFC6902.

Original CycloneDX JSON BOM file: [test/patch/cdx-1-5-simplest-base.json](test/patch/cdx-1-5-simplest-base.json) with `version` equal to `1`:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
      ...
  }
}
```

IETF RFC6902 JSON Patch file: [test/patch/cdx-patch-example-add-serial-number.json](test/patch/cdx-patch-example-add-serial-number.json):

```json
[
  { "op": "add", "path": "/version", "value": 2 }
]
```

Invoke the patch command as follows:

```bash
./sbom-utility patch --input-file test/patch/cdx-1-5-simplest-base.json --patch-file test/patch/cdx-patch-example-add-update-version.json  -q
```

The patched, output JSON BOM file which has the changed `version` value of `2`:

```json
{
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 2,
    "metadata": {
        ...
    }
}
```

##### Patch example 3: "add" `supplier` object to `metadata` object

This example shows how the patch's "add" operation can be used to add a JSON object to an existing object.

Original CycloneDX JSON BOM file: [test/patch/cdx-1-5-simplest-base.json](test/patch/cdx-1-5-simplest-base.json):

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "timestamp": "2023-10-12T19:07:00Z",
    "properties": [
      ...
    ]
  }
}
```

Apply the following IETF RFC6902 JSON Patch file: [test/patch/cdx-patch-example-add-metadata-supplier.json](test/patch/cdx-patch-example-add-metadata-supplier.json):

```json
[
  { "op": "add", "path": "/metadata/supplier", "value": {
      "name": "Example Co. Distribution Dept.",
      "url": [
        "https://example.com/software/"
      ]
    }
  }
]
```

Invoke the patch command as follows:

```bash
./sbom-utility patch --input-file test/patch/cdx-1-5-simplest-base.json --patch-file test/patch/cdx-patch-example-add-metadata-supplier.json -q
```

The patched BOM has the `supplier` object added to the `metadata`:

```json
{
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 1,
    "metadata": {
        "timestamp": "2023-10-12T19:07:00Z",
        "supplier": {
            "name": "Example Co. Distribution Dept.",
            "url": [
                "https://example.com/software/"
            ]
        },
        "properties": [
            ...
        ]
    }
}
```

##### Patch example 4: "add" `property` objects to `metadata.properties` array

This example shows how the patch's "add" operation can be used to add `property` objects to an existing `properties` array.

Original CycloneDX JSON BOM file: [test/patch/cdx-1-5-simplest-base.json](test/patch/cdx-1-5-simplest-base.json):

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "timestamp": "2023-10-12T19:07:00Z",
    "properties": [
      {
        "name": "Property 1",
        "value": "Value 1"
      },
      {
        "name": "Property 2",
        "value": "Value 2"
      }
    ]
  }
}
```

Apply the following IETF RFC6902 JSON Patch file: [test/patch/cdx-patch-example-add-metadata-properties.json](test/patch/cdx-patch-example-add-metadata-properties.json):

```json
[
  { "op": "add", "path": "/metadata/properties/-", "value": { "name": "foo", "value": "bar" } },
  { "op": "add", "path": "/metadata/properties/1", "value": { "name": "rush", "value": "yyz" } }
]
```

Note that the first patch record uses the `-` (dash) to indicate "insert at end" whereas the second patch record has the zero-based array index `1`.

Invoke the patch command as follows:

```bash
./sbom-utility patch --input-file test/patch/cdx-1-5-simplest-base.json --patch-file test/patch/cdx-patch-example-add-metadata-properties.json -q
```

The patched, output BOM has the two new properties at the specified indices:

```json
{
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 1,
    "metadata": {
        "timestamp": "2023-10-12T19:07:00Z",
        "properties": [
            {
                "name": "Property 1",
                "value": "Value 1"
            },
            {
                "name": "rush",
                "value": "yyz"
            },
            {
                "name": "Property 2",
                "value": "Value 2"
            },
            {
                "name": "foo",
                "value": "bar"
            }
        ]
    }
}
```

##### Patch example 5: "replace" BOM `version` and `timestamp`

This example shows how the patch's "replace" operation can be used to update the BOM document's `version` and `timestamp` values.

Original CycloneDX JSON BOM file: [test/patch/cdx-1-5-simplest-base.json](test/patch/cdx-1-5-simplest-base.json):

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "timestamp": "2023-10-12T19:07:00Z",
    "properties": [
      ...
    ]
  }
}
```

Apply the following IETF RFC6902 JSON Patch file: [test/patch/cdx-patch-example-replace-version-timestamp.json](test/patch/cdx-patch-example-replace-version-timestamp.json):

```json
[
  { "op": "replace", "path": "/version", "value": 2 },
  { "op": "replace", "path": "/metadata/timestamp", "value": "2024-01-24T22:50:18+00:00" }
]
```

Invoke the patch command as follows:

```bash
./sbom-utility patch --input-file test/patch/cdx-1-5-simplest-base.json --patch-file test/patch/cdx-patch-example-replace-version-timestamp.json -q
```

The patched, output BOM has both an updated `version` and `timestamp`:

```json
{
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 2,
    "metadata": {
        "timestamp": "2024-01-24T22:50:18+00:00",
        "properties": [
          ...
    }
}
```

##### Patch example 6: "remove" `property` from the `metadata.properties` array

This example shows how the patch's "remove" operation can be used to remove a `property` object from the `metadata.properties` array using an index.

Original CycloneDX JSON BOM file: [test/patch/cdx-1-5-simplest-base.json](test/patch/cdx-1-5-simplest-base.json):

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "timestamp": "2023-10-12T19:07:00Z",
    "properties": [
      {
        "name": "Property 1",
        "value": "Value 1"
      },
      {
        "name": "Property 2",
        "value": "Value 2"
      }
    ]
  }
}
```

Apply the following IETF RFC6902 JSON Patch file: [test/patch/cdx-patch-example-remove-metadata-property.json](test/patch/cdx-patch-example-remove-metadata-property.json):

```json
[
  { "op": "remove", "path": "/metadata/properties/1" }
]
```

Invoke the patch command as follows:

```bash
./sbom-utility patch --input-file test/patch/cdx-1-5-simplest-base.json --patch-file test/patch/cdx-patch-example-remove-metadata-property.json -q
```

The `property` at index `1` of the `metadata.properties` array has been removed:

```json
{
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 1,
    "metadata": {
        "timestamp": "2023-10-12T19:07:00Z",
        "properties": [
            {
                "name": "Property 1",
                "value": "Value 1"
            }
        ]
    }
}
```

##### Patch example 7: "test" `property` exists in the `metadata.properties` array

This example shows how the patch records's can "test" for values or objects in a BOM.  The utility will confirm "success" (using an `[INFO]` log message); otherwise, the utility will exit and return an error and generate an `[ERROR]` log message.

Original CycloneDX JSON BOM file: [test/patch/cdx-1-5-simplest-base.json](test/patch/cdx-1-5-simplest-base.json):

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "timestamp": "2023-10-12T19:07:00Z",
    "properties": [
      {
        "name": "Property 1",
        "value": "Value 1"
      },
      {
        "name": "Property 2",
        "value": "Value 2"
      }
    ]
  }
}
```

Apply the following IETF RFC6902 JSON Patch file: [test/patch/cdx-patch-example-test-metadata-property.json](test/patch/cdx-patch-example-test-metadata-property.json):

```json
[
  { "op": "test", "path": "/metadata/properties/1", "value":
    {
      "name": "Property 2",
      "value": "Value 2"
    }
  }
]
```

Invoke the patch command as follows:

```bash
./sbom-utility patch --input-file test/patch/cdx-1-5-simplest-base.json --patch-file test/patch/cdx-patch-example-test-metadata-property.json -q
```

An informational (i.e., `[INFO]`) message is logged with `success` since the property object was found in the input BOM:

```json
[INFO] IETF RFC6902 test operation success. test record: {
    "op": "test",
    "path": "/metadata/properties/1",
    "value": {
        "name": "Property 2",
        "value": "Value 2"
    }
}
```

If instead, we [tested for a different property](test/patch/cdx-patch-example-test-metadata-property-err.json) object:

```json
[
  { "op": "test", "path": "/metadata/properties/1", "value":
    {
      "name": "Property 3",
      "value": "Value 3"
    }
  }
]
```

an error (i.e., `[ERROR]`) would be returned from the utility:

```json
[ERROR] IETF RFC6902 test operation error. test record: {
    "op": "test",
    "path": "/metadata/properties/1",
    "value": {
        "name": "Property 3",
        "value": "Value 3"
    }
}
```

---

### Design considerations

#### Memory safety

The utility itself is written in `Go` to advantage the language's built-in typing enforcement and memory safe features and its ability to be compiled for a wide range of target platforms and architectures.

#### Consistent output

The utility also is designed to produce output formats (e.g., JSON) and handle exit codes consistently to make it immediately useful standalone or as part of automated Continuous Integration (CI) tool chains for downstream use or inspection.

#### Security and integrity focus

Further commands and reports are planned that prioritize use cases that enable greater insight and analysis of the legal, security and compliance data captured in the SBOM such as component **provenance** and **signage** (e.g., verifying resource identities by hashes or fingerprints).

In addition, inclusion of **Continuous Integration and Delivery (CI/CD)** or "build integrity" information around the BOM component is anticipated as part of the CycloneDX Formulation work which will require features for workflow insights.

#### Functional priorities

The utility additionally prioritizes commands that help provide insight into contents of the BOM to search for and report on missing (i.e., completeness) or specific data requirements (e.g., organization or customer-specific requirements).

In general, the goal of these prioritized commands is to support data verification for many of the primary BOM use cases as identified by the CycloneDX community (see https://cyclonedx.org/use-cases/).  Functional development has focused on those use cases that verify inventory (resource identity), legal compliance (e.g., license), and security analysis (e.g., vulnerability) which are foundational to any SBOM.

#### Support all BOM formats

In the future, we envision support for additional kinds of BOMs (e.g., Hardware (HBOM), Machine Learning (MLBOM), etc.) with each again having different data requirements and levels of maturity which will increase the need for domain-specific validation.  Specifically, this utility intends to support the work of the [OWASP Software Component Verification Standard (SCVS)](https://owasp.org/www-project-software-component-verification-standard/) which is defining a BOM Maturity Model (BMM).

---

### Development

#### Prerequisites

- Go v1.20.1 or higher: see [https://go.dev/doc/install](https://go.dev/doc/install)
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
-rwxr-xr-x   1 User1  staff  11501122 Jan 24 08:29 sbom-utility
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

The utility uses the [`config.json`](./config.json) file (either the default, embedded version or the equivalent provided on the command line using `--config-schema` flag) to lookup supported formats and their associated versioned JSON schema files.  To add another SBOM format simply add another entry to the `format` array in the root of the document:

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

- **Merge command** Support merge of two (both validated) SBOMs with de-duplication and configurable. Please note that some method of normalization prior to merge will be necessary.
- **Remote Schema loading** Support using SBOM schema files that are remotely hosted  (network accessible) from known, trusted source locations (e.g., releases of SPDX, CycloneDX specification schemas). Note that the config file has an existing `url` field per entry that can be used for this purpose.
- **--orderby** Support ordering of query result sets by comparison of values from a specified field key.
- **license.json** Document license policy configuration JSON schema structure and how to add entries relative to a CycloneDX `LicenseChoice` object for entries with SPDX IDs and those without.
- **license.json** Add entries for all SPDX licenses listed in v3.21.
  - See issue: https://github.com/CycloneDX/sbom-utility/issues/12
- **Go libraries** Replace `go-prettyjson`, `go-multimap` libraries with alternatives that produce maintained releases.

---

### Supporting new SBOM formats and schema versions

The utility uses the [`config.json`](./config.json) file to lookup supported BOM formats and their associated versioned schemas.  To add another SBOM format simply add another entry to the `format` array in the root of the document:

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

The fields `canonicalName`, `propertyKeyFormat`, `propertyKeyVersion`, and `propertyValueFormat` are required. The `format` object **MUST** have at least one valid `schema` object.

An example `schema` object for the canonical SPDX v2.3 (default, no variant) schema appears as follows:

```json
{
  {
      "version": "SPDX-2.3",
      "variant": "",
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

### Go test files

The built-in `go test` command is used to execute all functional tests that appear in `*._test.go` files.  By default, `go test` executes tests within the same directory where its respective `*._test.go` file is located and sets that as the working directory. For example, tests in the `validate_test.go` file are executed from the `cmd` subdirectory. This is a problem as the actual test SBOM JSON test files are located relative the project root, one level higher, and would not be found.  In order to correct for that, the test working directory is automatically changed for all tests within the `TestMain` routine found in `root_test.go`.

### Running tests

The `Makefile` includes a `test` target for convenience which will use `go test` to run all tests found in all subdirectories:

```bash
make test
```

#### Running tests for a single package

The `test_cmd` target will use run only the test found in the `cmd` package:

```bash
make test_cmd
```

The `test_schema` target will use run only the test found in the `schema` package:

```bash
make test_schema
```

#### Using `go test`

Example: running all tests in the `cmd` package:

```bash
go test github.com/CycloneDX/sbom-utility/cmd -v
```

Example: running all tests in the `schema` package:

```bash
go test github.com/CycloneDX/sbom-utility/schema -v
```

#### Running tests in quiet mode

Run in "quiet" mode to not see error test output:

```bash
go test github.com/CycloneDX/sbom-utility/cmd -v --quiet
```

run an individual test within the `cmd` package:

```bash
go test github.com/CycloneDX/sbom-utility/cmd -v -run TestValidateCdx14MinRequiredBasic
```

##### Debugging `go test`

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

- [https://github.com/CycloneDX/sbom-utility/releases](https://github.com/CycloneDX/sbom-utility/releases)

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
    - [v2.3.1](https://github.com/spdx/spdx-spec/tree/development/v2.3.1/schemas)
    - [v2.3](https://github.com/spdx/spdx-spec/tree/development/v2.3/schemas)
    - [v2.2.2](https://github.com/spdx/spdx-spec/tree/development/v2.2.2/schemas)
  - SPDX Examples: [https://github.com/spdx/spdx-examples](https://github.com/spdx/spdx-examples)

- Tools
  - [SPDX Online Tool](https://tools.spdx.org/app/)
    - **Note** Used the [convert](https://tools.spdx.org/app/convert/) tool to convert SPDX examples from `.tv` format to `.json`; however, conversion of [`example6-bin.spdx`](https://github.com/spdx/spdx-examples/blob/master/example6/spdx/example6-bin.spdx) resulted in an error.

### Software-Bill-of-Materials (SBOM)

- [NTIA - SBOM Minimum Requirements](https://www.ntia.doc.gov/blog/2021/ntia-releases-minimum-elements-software-bill-materials)
- [CISA - Software Bill of Materials (SBOM)](https://www.cisa.gov/sbom)
- [FOSSA - Software Bill Of Materials: Formats, Use Cases, and Tools](https://fossa.com/blog/software-bill-of-materials-formats-use-cases-tools/)

#### Guides

- [FOSSA](https://fossa.com/)
  - *["A Practical Guide to CycloneDX"](https://fossa.com/cyclonedx)*
