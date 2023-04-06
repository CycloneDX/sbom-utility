# sbom-utility demo

This document will demonstrate key commands and flags supported by the sbom-utility.

## Commands and flags covered

- [`schema` command](#schema-command)
- [Persistent flags and codes](#persistent-flags-and-codes)
  - [quiet flag](#quiet-flag): with `--quiet` or `-q`
  - [format flag](#format-flag): with `--format`
  - [output flag](#output-flag): with `--output` or `-o`
  - [exit codes](#exit-codes): `0` == no error, `1` == app. error, `2` == validation error
- [`validate` command](#validate-command)
- [`resource` command](#resource-command)
- [`license` command](#license-command)
  - [policy](#policy-subcommand) subcommand
  - [list](#list-subcommand) subcommand
    - [summary flag](#example-summary-flag): list with the `--summary` flag
- [`vulnerability` command](#vulnerability-command)
- [`query` command](#query-command)

---

### `schema` command

You can verify which format-based schemas versions and variants are available for validation by using the `schema list` command:

```bash
./sbom-utility schema list
```

```bash
Welcome to the sbom-utility! Version `latest` (sbom-utility) (darwin/arm64)
===========================================================================
[INFO] Loading license policy config file: `license.json`...
Name                          Format     Version   Variant      File (local)                                     URL (remote)
----                          ------     -------   -------      ------------                                     ------------
CycloneDX v1.5 (development)  CycloneDX  1.5       development  schema/cyclonedx/1.5/bom-1.5-dev.schema.json     https://raw.githubusercontent.com/CycloneDX/specification/v1.5-dev/schema/bom-1.5.schema.json
CycloneDX v1.4 (custom)       CycloneDX  1.4       custom       schema/test/bom-1.4-custom.schema.json
CycloneDX v1.4                CycloneDX  1.4       (latest)     schema/cyclonedx/1.4/bom-1.4.schema.json         https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.4.schema.json
CycloneDX v1.3 (strict)       CycloneDX  1.3       strict       schema/cyclonedx/1.3/bom-1.3-strict.schema.json  https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.3-strict.schema.json
CycloneDX v1.3 (custom)       CycloneDX  1.3       custom       schema/test/bom-1.3-custom.schema.json
CycloneDX v1.3                CycloneDX  1.3       (latest)     schema/cyclonedx/1.3/bom-1.3.schema.json         https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.3.schema.json
CycloneDX v1.2 (strict)       CycloneDX  1.2       strict       schema/cyclonedx/1.2/bom-1.2-strict.schema.json  https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.2-strict.schema.json
CycloneDX v1.2                CycloneDX  1.2       (latest)     schema/cyclonedx/1.2/bom-1.2.schema.json         https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.2.schema.json
SPDX v2.3.1 (development)     SPDX       SPDX-2.3  development  schema/spdx/2.3.1/spdx-schema.json               https://raw.githubusercontent.com/spdx/spdx-spec/development/v2.3.1/schemas/spdx-schema.json
SPDX v2.3                     SPDX       SPDX-2.3  (latest)     schema/spdx/2.3/spdx-schema.json                 https://raw.githubusercontent.com/spdx/spdx-spec/development/v2.3/schemas/spdx-schema.json
SPDX v2.2.2                   SPDX       SPDX-2.2  (latest)     schema/spdx/2.2.2/spdx-schema.json               https://raw.githubusercontent.com/spdx/spdx-spec/v2.2.2/schemas/spdx-schema.json
SPDX v2.2.1                   SPDX       SPDX-2.2  2.2.1        schema/spdx/2.2.1/spdx-schema.json               https://raw.githubusercontent.com/spdx/spdx-spec/v2.2.1/schemas/spdx-schema.json
```

- These are declared in the [`config.json`](https://github.com/CycloneDX/sbom-utility/blob/main/config.json) file.
- Built-in (embedded) JSON schemas can be found in the [`resources`](https://github.com/CycloneDX/sbom-utility/tree/main/resources)/[`schema`](https://github.com/CycloneDX/sbom-utility/tree/main/resources/schema) directory.

---

## Persistent flags and codes

The following examples show flags that apply to any command that produces a list or report as well as exit codes from all commands.

### Quiet flag

By default, the utility outputs informational and processing text as well as any results of the command to `stdout`.  If you wish to only see the command results (JSON) or report (tables) you can run any command in "quiet mode" by simply supplying the `--quiet` or its short-form `-q` flag.

#### Example: quiet flag

This example shows the `--quiet` flag being used on the `schema` command to turn off or "quiet" any informational output so that only the result table is displayed.

```bash
./sbom-utility schema --quiet
```

```bash
Name                          Format     Version   Variant      File (local)                                     URL (remote)
----                          ------     -------   -------      ------------                                     ------------
CycloneDX v1.5 (development)  CycloneDX  1.5       development  schema/cyclonedx/1.5/bom-1.5-dev.schema.json     https://raw.githubusercontent.com/CycloneDX/specification/v1.5-dev/schema/bom-1.5.schema.json
CycloneDX v1.4 (custom)       CycloneDX  1.4       custom       schema/test/bom-1.4-custom.schema.json
CycloneDX v1.4                CycloneDX  1.4       (latest)     schema/cyclonedx/1.4/bom-1.4.schema.json         https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.4.schema.json
CycloneDX v1.3 (strict)       CycloneDX  1.3       strict       schema/cyclonedx/1.3/bom-1.3-strict.schema.json  https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.3-strict.schema.json
CycloneDX v1.3 (custom)       CycloneDX  1.3       custom       schema/test/bom-1.3-custom.schema.json
CycloneDX v1.3                CycloneDX  1.3       (latest)     schema/cyclonedx/1.3/bom-1.3.schema.json         https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.3.schema.json
CycloneDX v1.2 (strict)       CycloneDX  1.2       strict       schema/cyclonedx/1.2/bom-1.2-strict.schema.json  https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.2-strict.schema.json
CycloneDX v1.2                CycloneDX  1.2       (latest)     schema/cyclonedx/1.2/bom-1.2.schema.json         https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.2.schema.json
SPDX v2.3.1 (development)     SPDX       SPDX-2.3  development  schema/spdx/2.3.1/spdx-schema.json               https://raw.githubusercontent.com/spdx/spdx-spec/development/v2.3.1/schemas/spdx-schema.json
SPDX v2.3                     SPDX       SPDX-2.3  (latest)     schema/spdx/2.3/spdx-schema.json                 https://raw.githubusercontent.com/spdx/spdx-spec/development/v2.3/schemas/spdx-schema.json
SPDX v2.2.2                   SPDX       SPDX-2.2  (latest)     schema/spdx/2.2.2/spdx-schema.json               https://raw.githubusercontent.com/spdx/spdx-spec/v2.2.2/schemas/spdx-schema.json
SPDX v2.2.1                   SPDX       SPDX-2.2  2.2.1        schema/spdx/2.2.1/spdx-schema.json               https://raw.githubusercontent.com/spdx/spdx-spec/v2.2.1/schemas/spdx-schema.json
```

### Format flag

All `list` commands support the `--format` flag with the following values:

- `txt`: text (tabbed tables)
- `csv`: Comma Separated Value (CSV), e.g., for spreadsheets
- `md`: Markdown, e.g., for GitHub

Some commands, which can output lists of JSON objects, also support JSON format using the `json` value.

#### Example: format flag

This example uses the `--format` flag on the `schema` command to output in markdown:

```bash
./sbom-utility schema --format md -q
```

```md
|Name|Format|Version|Variant|File (local)|URL (remote)|
|:--|:--|:--|:--|:--|:--|
|CycloneDX v1.5 (development)|CycloneDX|1.5|development|schema/cyclonedx/1.5/bom-1.5-dev.schema.json|https://raw.githubusercontent.com/CycloneDX/specification/v1.5-dev/schema/bom-1.5.schema.json|
|CycloneDX v1.4 (custom)|CycloneDX|1.4|custom|schema/test/bom-1.4-custom.schema.json||
|CycloneDX v1.4|CycloneDX|1.4|(latest)|schema/cyclonedx/1.4/bom-1.4.schema.json|https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.4.schema.json|
|CycloneDX v1.3 (strict)|CycloneDX|1.3|strict|schema/cyclonedx/1.3/bom-1.3-strict.schema.json|https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.3-strict.schema.json|
|CycloneDX v1.3 (custom)|CycloneDX|1.3|custom|schema/test/bom-1.3-custom.schema.json||
|CycloneDX v1.3|CycloneDX|1.3|(latest)|schema/cyclonedx/1.3/bom-1.3.schema.json|https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.3.schema.json|
|CycloneDX v1.2 (strict)|CycloneDX|1.2|strict|schema/cyclonedx/1.2/bom-1.2-strict.schema.json|https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.2-strict.schema.json|
|CycloneDX v1.2|CycloneDX|1.2|(latest)|schema/cyclonedx/1.2/bom-1.2.schema.json|https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.2.schema.json|
|SPDX v2.3.1 (development)|SPDX|SPDX-2.3|development|schema/spdx/2.3.1/spdx-schema.json|https://raw.githubusercontent.com/spdx/spdx-spec/development/v2.3.1/schemas/spdx-schema.json|
|SPDX v2.3|SPDX|SPDX-2.3|(latest)|schema/spdx/2.3/spdx-schema.json|https://raw.githubusercontent.com/spdx/spdx-spec/development/v2.3/schemas/spdx-schema.json|
|SPDX v2.2.2|SPDX|SPDX-2.2|(latest)|schema/spdx/2.2.2/spdx-schema.json|https://raw.githubusercontent.com/spdx/spdx-spec/v2.2.2/schemas/spdx-schema.json|
|SPDX v2.2.1|SPDX|SPDX-2.2|2.2.1|schema/spdx/2.2.1/spdx-schema.json|https://raw.githubusercontent.com/spdx/spdx-spec/v2.2.1/schemas/spdx-schema.json|
```

### Output flag

All commands support the `-o <filename>` (or its long form `--output-file`) flag to send formatted output to a file.

#### Example: output flag

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
CycloneDX v1.4 (custom),CycloneDX,1.4,custom,schema/test/bom-1.4-custom.schema.json,
CycloneDX v1.4,CycloneDX,1.4,(latest),schema/cyclonedx/1.4/bom-1.4.schema.json,https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.4.schema.json
CycloneDX v1.3 (strict),CycloneDX,1.3,strict,schema/cyclonedx/1.3/bom-1.3-strict.schema.json,https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.3-strict.schema.json
CycloneDX v1.3 (custom),CycloneDX,1.3,custom,schema/test/bom-1.3-custom.schema.json,
CycloneDX v1.3,CycloneDX,1.3,(latest),schema/cyclonedx/1.3/bom-1.3.schema.json,https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.3.schema.json
CycloneDX v1.2 (strict),CycloneDX,1.2,strict,schema/cyclonedx/1.2/bom-1.2-strict.schema.json,https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.2-strict.schema.json
CycloneDX v1.2,CycloneDX,1.2,(latest),schema/cyclonedx/1.2/bom-1.2.schema.json,https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.2.schema.json
SPDX v2.3.1 (development),SPDX,SPDX-2.3,development,schema/spdx/2.3.1/spdx-schema.json,https://raw.githubusercontent.com/spdx/spdx-spec/development/v2.3.1/schemas/spdx-schema.json
SPDX v2.3,SPDX,SPDX-2.3,(latest),schema/spdx/2.3/spdx-schema.json,https://raw.githubusercontent.com/spdx/spdx-spec/development/v2.3/schemas/spdx-schema.json
SPDX v2.2.2,SPDX,SPDX-2.2,(latest),schema/spdx/2.2.2/spdx-schema.json,https://raw.githubusercontent.com/spdx/spdx-spec/v2.2.2/schemas/spdx-schema.json
SPDX v2.2.1,SPDX,SPDX-2.2,2.2.1,schema/spdx/2.2.1/spdx-schema.json,https://raw.githubusercontent.com/spdx/spdx-spec/v2.2.1/schemas/spdx-schema.json
```

- You can verify that `output.csv` loads within a spreadsheet app like MS Excel.

### Exit codes

All commands return a numeric exit code (i.e., a POSIX exit code) for use in automated processing where `0` indicates success and a non-zero value indicates failure of some kind designated by the number.

The SBOM Utility always returns one of these 3 codes to accommodate logic in BASH (shell) scripting:

- `0`= no error (valid)
- `1`= application error
- `2`= validation error

#### Example: exit code

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

---

### `validate` command

This command will parse standardized SBOMs and validate it against its declared format and version (e.g., SPDX 2.2, CycloneDX 1.4).

#### Validate an SPDX SBOM

Validate SPDX's "example 1" SBOM example (i.e., [`examples/spdx/example1/example1.json`](https://github.com/CycloneDX/sbom-utility/blob/main/examples/spdx/example1/example1.json)) by passing in its relative filename on the `--input` or `-i` flag:

```bash
./sbom-utility validate --input-file examples/spdx/example1/example1.json
```

```bash
Welcome to the sbom-utility! Version `latest` (sbom-utility) (darwin/arm64)
===========================================================================
[INFO] Loading license policy config file: `license.json`...
[INFO] Attempting to load and unmarshal file `examples/spdx/example1/example1.json`...
[INFO] Successfully unmarshalled data from: `examples/spdx/example1/example1.json`
[INFO] Determining file's SBOM format and version...
[INFO] Determined SBOM format, version (variant): `SPDX`, `SPDX-2.2` (latest)
[INFO] Matching SBOM schema (for validation): schema/spdx/2.2.2/spdx-schema.json
[INFO] Loading schema `schema/spdx/2.2.2/spdx-schema.json`...
[INFO] Schema `schema/spdx/2.2.2/spdx-schema.json` loaded.
[INFO] Validating `examples/spdx/example1/example1.json`...
[INFO] SBOM valid against JSON schema: `true`
```

- **Note** The SPDX format and version inferred from the document header and used the `latest` schema to validate

#### Validate a CycloneDX SBOM

Validate the CycloneDX "juice shop" SBOM example (i.e., [`examples/cyclonedx/BOM/juice-shop-11.1.2/bom.json`](https://github.com/CycloneDX/sbom-utility/tree/main/examples/cyclonedx/BOM/juice-shop-11.1.2)) by passing in its relative filename on the `--input` or `-i` flag:

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

- **Note** The CycloneDX format and version inferred from the document header and used the `latest` schema to validate

##### Verify the exit code indicates it was valid as well

```bash
echo $?
```

```bash
0  // no error (valid)
```

#### Example: Using a "custom" schema variant

The validation command will use the declared format and version found within the SBOM JSON file itself to lookup the default (latest) matching schema version (as declared in`config.json`; however, if variants of that same schema (same format and version) are declared, they can be requested via the `--variant` command line flag.

First, try validating a "mature" CycloneDX v1.4 SBOM without the `--variant` flag:

```bash
./sbom-utility validate -i test/cyclonedx/cdx-1-4-mature-example-1.json
```

and see that the `latest` CycloneDX v1.4 schema was used:

```bash
[INFO] Determined SBOM format, version (variant): `CycloneDX`, `1.4` (latest)
[INFO] Matching SBOM schema (for validation): schema/cyclonedx/1.4/bom-1.4.schema.json
[INFO] Loading schema `schema/cyclonedx/1.4/bom-1.4.schema.json`...
[INFO] Schema `schema/cyclonedx/1.4/bom-1.4.schema.json` loaded.
[INFO] Validating `test/cyclonedx/cdx-1-4-mature-example-1.json`...
[INFO] SBOM valid against JSON schema: `true`
```

Try it with the flag:

```bash
./sbom-utility validate -i test/cyclonedx/cdx-1-4-mature-example-1.json --variant custom
```

as you can see, the `schema/test/bom-1.4-custom.schema.json` schema variant was used:

```bash
[INFO] Determined SBOM format, version (variant): `CycloneDX`, `1.4` custom
[INFO] Matching SBOM schema (for validation): schema/test/bom-1.4-custom.schema.json
[INFO] Loading schema `schema/test/bom-1.4-custom.schema.json`...
[INFO] Schema `schema/test/bom-1.4-custom.schema.json` loaded.
[INFO] Validating `test/cyclonedx/cdx-1-4-mature-example-1.json`...
[INFO] SBOM valid against JSON schema: `true`
```

#### Example: schema validation failure

Let us use the `--variant custom` flag and explore a schema failure against another CycloneDX v1.4 SBOM:

```bash
./sbom-utility validate -i test/custom/cdx-1-4-test-custom-metadata-property-disclaimer-invalid.json --variant custom
```

If you run the sample command above, you would see several "custom" schema errors resulting in an invalid SBOM determination (i.e., `exit status 2`):

```bash
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

##### Check last validate command's exit code

```bash
echo $?
```

```
2  // validation error
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
	3. Type: [number_all_of], Field: [metadata.properties], Description: [Must validate all the schemas (allOf)]
	Failing object: [[
	  {
	    "name": "urn:example.com:disclaimer",
	    "value": "This SBOM is current as of the date it was generated."
	  },
	  {
	    "name": "urn:example.com:classification",
	    "value": "This SBOM is Confidential Information. Do not distribute."
	  }
	]]
```

---

### `resource` command

The `resource` command is geared toward inspecting various resources types and their information from SBOMs against future maturity models being developed as part of the [OWASP Software Component Verification Standard (SCVS)](https://owasp.org/www-project-software-component-verification-standard/).

In the SCVS model, a "resource" is the parent classification for software (components), services, Machine Learning (ML) models, data, hardware, tools and more.

##### Example: `list` add resources

Primarily, the command is used to generate lists of resources, by type, that are included in a CycloneDX BOM by invoking `resource list`:

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

##### Example: `list` all services using the `--type` flag

This example uses the `type` flag to limit results to only `service` resources:

```bash
./sbom-utility resource list -i test/cyclonedx/cdx-1-3-resource-list.json --type service --quiet
```

```bash
type     name    version  bom-ref
----     ----    -------  -------
service  Bar              service:example.com/myservices/bar
service  Foo              service:example.com/myservices/foo
```

- **Note**: Currently, valid `--type` values include `service` and `component` until expanded by the SCVS model.

#### Example: `list` all components using the `--where` flag

The `where` flag can be used to supply regular expressions (regex) to filter report results using any column title (i.e., `type`, `name`, `version` or `bom-ref`) supported by the `resource` command:

```bash
./sbom-utility resource list -i test/cyclonedx/cdx-1-3-resource-list.json --where type=component --quiet
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
```

- **Note**: Using the `--where type=component` flag is equivalent to using the `--type component` flag which is provided as a convenience.

##### Example: `list` resources with matching `name` using the `--where` flag

This example uses the `where` filter on the `name` field. In this case we supply an exact "startswith" regex. for the `name` filter.

```bash
./sbom-utility resource list -i test/cyclonedx/cdx-1-3-resource-list.json --where "name=Library A" --quiet
```

```bash
type       name       version  bom-ref
----       ----       -------  -------
component  Library A  1.0.0    pkg:lib/libraryA@1.0.0
```

- **Note**: Double quotes were used to assure the space character in the name "Library A" was part of the matching value.

---

### `license` command

This command is used to aggregate and summarize software, hardware and data license information included in the SBOM. It also displays license usage policies for resources based upon concluded by SPDX license identifier, license family or logical license expressions as defined in he current policy file (i.e., `license.json`).

#### `policy` subcommand

To view a report listing the contents of the current policy file (i.e., [`license.json`](https://github.com/CycloneDX/sbom-utility/blob/main/license.json)) which contains an encoding of known software and data licenses by SPDX ID and license family along with a configurable usage policy (i.e., `"allow"`, `"deny"` or `"needs-review"`) use:

```bash
./sbom-utility license policy --quiet
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

- **Note**:
  - Currently, the default `license.json` file does not contain an entry for the complete SPDX 3.2 license templates. An issue [12](https://github.com/CycloneDX/sbom-utility/issues/12) is open to add parity.
  - Annotations can be defined within the `license.json` file and one or more assigned each license entry.

#### `list` subcommand

This subcommand will emit a list of all licenses found in and SBOM (defaults to `json` format):

```bash
./sbom-utility license list -i examples/cyclonedx/BOM/juice-shop-11.1.2/bom.json
```

The output will be an `json` format array of CycloneDX `LicenseChoice` data structures.  For example, you would see licenses identified using SPDX IDs, license expressions (of SPDX IDs) or ones with "names" of licenses that do not necessarily map to a canonical SPDX ID along with the actual base64-encoded license or legal text.

For example, the output includes all three types of license data you would see (by `id`, by `name` and by `expression`):

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

##### Example: Summary flag

Use the `--summary` flag on the `license list` command to produce a summary report in `txt` (default) format as well as license `usage policy` determination based upon the `license.json` declarations:

```bash
./sbom-utility license list -i test/cyclonedx/cdx-1-3-license-list.json --summary --quiet
```

as you can see, the default output is in `txt` format and includes a `usage policy` determination:

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

- **Note**
  - **Usage policy** column values are derived from the `license.json` policy configuration file.
    - A `usage policy` value of `UNDEFINED` indicates that `license.json` provided no entry that matched the declared license (`id` or `name`) in the SBOM.
  - **License expressions** (e.g., `(MIT or GPL-2.0)`) with one term resolving to `UNDEFINED` and the the other term having a concrete policy will resolve to the "optimistic" policy for `OR` expressions and the "pessimistic" policy for `AND` expressions.  In addition, a warning of this resolution is emitted.

#### Examples: Filtering using `--where` flag

The list command results can be filtered using the `--where` flag using the column names in the report. These include `usage-policy`, `license-type`, `license`, `resource-name`, `bom-ref` and `bom-location`.

The following example shows filtering of resource licenses using the `license-type` column where the license identified using a `name` value:

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

### `vulnerability` command

This command will extract basic vulnerability report data from an SBOM that has a "vulnerabilities" list or from a standalone VEX in CycloneDX format. It includes the ability to filter reports data by applying regex to any of the named column data.

**Note**: More column data and flags to filter results are planned.

#### Where flag filtering

In addition a `where` filter flag can be supplied to only include results where values match supplied regex.  Supported keys for the `where` filter include the following column names in the report (i.e., `id`, `bom-ref`, `source-name`, `source-url`, `created`, `published`, `updated`, `rejected` and `description`).

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
id              bom-ref  source-name  source-url                                      created                   published                 updated                   rejected  description
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
id              bom-ref  source-name  source-url                                      created                   published                 updated                   rejected  description
--              -------  ----------  -----------                                      -------                   ---------                 -------                   --------  -----------
CVE-2020-25649           NVD         https://nvd.nist.gov/vuln/detail/CVE-2020-25649  2020-12-03T00:00:00.000Z  2020-12-03T00:00:00.000Z  2023-02-02T00:00:00.000Z            com.fasterxml.jackson.core:jackson-databind is a library which contains the general-purpose data-binding functionality and tree-model for Jackson Data Processor.  Affected versions of this package are vulnerable to XML External Entity (XXE) Injection.
```

---

### `query` command

This command allows you to perform SQL-like queries into JSON format SBOMs.  Currently, the command recognizes the `--select` and `--from` as well as the `--where` filter.

The `--from` clause value is applied to the JSON document object model and can return either a singleton JSON object or an array of JSON objects as a result.  This is determined by the last property value's type as declared in the schema.

The `--select` clause is then applied to the `--from` result set to only return the specified properties (names and their values).

If the result set is an array, the array entries can be reduced by applying the `--where` filter to ony return those entries whose specified field names match the supplied regular expression (regex).

**Note**: All `query` command results are returned as valid JSON documents.  This includes a `null` value for empty result sets.

##### Example: Select a JSON object using the `--from` flag only

In this example, only the `--from` clause is needed to select an object.  The `--select` clause is omitted which is equivalent to using the "select all" wildcard character `*` which returns all fields and values from the object.

```bash
./sbom-utility query -i test/cyclonedx/cdx-1-4-mature-example-1.json --from metadata.component --quiet
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

**Note** the command above is equivalent to using the wildcard character (`*`) which may need to be enclosed in single or double quotes depending on your shell:

```bash
./sbom-utility query -i test/cyclonedx/cdx-1-4-mature-example-1.json --select '*' --from metadata.component --quiet
```

##### Example: Select fields from JSON object

In this example, the `--from` clause references the  singleton JSON object `component` found under the top-level `metadata` object. It then reduces the resultant JSON object to only return the `name` and `value` fields and their values as requested on the `--select` clause.

```bash
./sbom-utility query --select name,version --from metadata.component -i examples/cyclonedx/BOM/juice-shop-11.1.2/bom.json --quiet
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
