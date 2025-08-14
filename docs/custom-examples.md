# Custom validation

In addition to validating the the BOM input file using the standard CycloneDX schema, you now can provide a custom JSON file that will apply a built-in set of validation functions to selected parts of the BOM document that can validate JSON elements, property keys and values.

#### Check functions

The current set of functions that can achieve this includes:

- `isUnique` - checks uniqueness of array items given a property name as key
- `hasProperties` - can verify that a named property exists on a selected JSON element and can also enforce the corresponding property has the expected value using regex.

**Note**: *More functions are planned for future releases if use cases are found.*

#### Usage

The minimum set of required command flags to invoke custom validation using the utility's `validate` command would be:

```bash
./sbom-utility validate -i <input-bom.json> --custom <custom-validation-config.json>
```

---

## Examples by function

Examples are provided for each custom validation function or "check":

- [`isUnique` examples](#isunique-examples) - used to validate array item uniqueness.
- [`hasProperties` examples](#hasproperties-examples) - used to validate that a selected JSON object has specified properties.

---

### `isUnique` examples

The `isUnique` function can be used to validate that an item in a JSON array is "unique" using a specified `primaryKey` property. The `primaryKey` property specifies the JSON map `key` used as the *primary key* for for items in the array and its `value` tested for uniqueness.

#### Example: Valid: `property` is unique in the `metadata.properties` array

Using the custom configuration file `test/custom/cdx-1-6-test-metedata-properties-disclaimer-examples.json` for this validation check is as follows;

```json
{
  "validation": {
    "actions": [
      {
        "id": "custom-metadata-properties-disclaimer-examples",
        "description": "Validate BOM metadata properties has a unique, specific disclaimer value.",
        "selector": {
          "path": "metadata.properties",
          "primaryKey": {
            "key": "name",
            "value": "urn:example.com:disclaimer"
          }
        },
        "functions": [
          "isUnique"
        ]
      }
    ]
  }
}
```

The `path` value of the `selector` object is set to `metadata.properties` and will be used to locate the JSON array that holds the `property` items.  As each item is a JSON map object, the `primaryKey` can be used to identify the map `key` (in this case the `name` map key) and `value` (i.e., `urn:example.com:disclaimer`) used to  identify the specific key value to validate as unique within the array.

When the custom validation configuration (above) is applied to the test CycloneDX BOM file: `test/custom/cdx-1-6-test-metedata-properties-disclaimer.json` with contents:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "timestamp": "2025-08-09T07:20:00.000Z",
    "component": {
      "type": "application",
      "name": "sample app"
    },
    "properties": [
      {
        "name": "urn:example.com:disclaimer",
        "value": "This SBOM is current as of the date it was generated and is subject to change."
      },
      {
        "name": "urn:example.com:classification",
        "value": "This SBOM is Confidential Information. Do not distribute."
      }
    ]
  }
}
```

and running it from the command line:

```bash
./sbom-utility validate -i test/custom/cdx-1-6-test-metedata-properties-disclaimer.json --custom test/custom/custom-metadata-properties-disclaimer-unique.json
```

it produces the following result:

```bash
[INFO] Validating 'test/custom/cdx-1-6-test-metedata-properties-disclaimer-examples.json'...
[INFO] BOM valid against JSON schema: 'true'
[INFO] Loading custom validation config file: 'test/custom/cdx-1-6-test-metedata-properties-disclaimer.json'...
[INFO] Validating custom action (id: `custom-metadata-properties-unique-disclaimer`, selector: `{ "path": "metadata.properties", "primaryKey": { "key": "name", "value": "urn:example.com:disclaimer" } }`)...
[INFO] >> Checking isUnique: (selector: `{metadata.properties {name urn:example.com:disclaimer}}`)...
[INFO] BOM valid against custom JSON configuration: 'test/custom/custom-metadata-properties-disclaimer-unique.json'
```

As you can see, the standard schema validation is first applied and returns "`BOM valid against JSON schema: 'true'`" then the custom checks are applied which also returns "`BOM valid against custom JSON configuration`" with the details of each check provided.

The `validate` command factors in the custom validation along with the normal schema validation when setting the exit code (i.e., `0`, zero in this valid case).  This preserves the ability to test exit code from the command line and within test scripts:

```
$ echo $?
0
```

---

#### Example: Invalid: `property` item is not unique in BOM `properties` array

Using the custom configuration file `test/custom/custom-bom-properties-not-unique.json` for this validation check is as follows;

```json
{
  "validation": {
    "actions": [
      {
        "id": "custom-bom-properties-not-unique",
        "description": "Validate BOM properties no unique",
        "selector": {
          "path": "properties",
          "primaryKey": {
            "key": "name",
            "value": "foo"
          }
        },
        "functions": [
          "isUnique"
        ]
      }
    ]
  }
}
```

When applied to the test CycloneDX BOM file: `test/custom/cdx-1-6-test-bom-properties.json`:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "timestamp": "2025-08-09T07:20:00.000Z",
    "component": {
      "name": "sample app",
      "type": "application"
    }
  },
  "properties": [
    {
      "name": "foo",
      "value": "bar1"
    },
    {
      "name": "foo",
      "value": "bar2"
    },
    {
      "name": "yyz",
      "value": "rush"
    }
  ]
}
```

and running it from the command line:

```bash
./sbom-utility validate -i test/custom/cdx-1-6-test-bom-properties.json --custom test/custom/custom-bom-properties-not-unique.json
```

produces the following result:

```bash
[INFO] BOM valid against JSON schema: 'true'
[INFO] Loading custom validation config file: 'test/custom/custom-bom-properties-not-unique.json'...
[INFO] Validating custom action (id: `custom-bom-properties-not-unique`, selector: `{ "path": "properties", "primaryKey": { "key": "name", "value": "foo" } }`)...
[INFO] >> Checking isUnique: (selector: `{properties {name foo}}`)...
[ERROR] invalid SBOM: custom validation failed: Function: 'isUnique', selector: { "path": "properties", "primaryKey": { "key": "name", "value": "foo" } }, matches found: 2 () (test/custom/cdx-1-6-test-bom-properties.json)
[INFO] document 'test/custom/cdx-1-6-test-bom-properties.json': valid=[false]
```

which indicates the `property` designated as the "primary key" (i.e., the `name` key) resulted in multiple (i.e., two (2)) items and therefore not unique.

Specifically, there are 2 CycloneDX `property` in the array items that have the `foo` value in the `name` key designated a the `primaryKey`.

In this invalid example, the exit code will reflect the custom validation failure with a non-zero exit code:

```bash
echo $?
2
```

---

### `hasProperties` examples

The `hasProperties` function can be used to validate that specific properties (i.e., key-value pairs) are present in a selected object within the BOM document.

#### Example: Valid: `metadata` has `timestamp`, `supplier`, `component` and `licenses` properties

Using the custom configuration file `test/custom/custom-metadata-has-elements.json` for this validation check is as follows;

```json
{
  "validation": {
    "actions": [
      {
        "id": "custom-test-metadata-has-elements",
        "description": "Test the 'metadata' element contains required child elements which are a mix of primitives and complex types.",
        "selector": {
          "path": "metadata"
        },
        "functions": [
          "hasProperties"
        ],
        "properties": [
          {
            "key": "timestamp"
          },
          {
            "key": "supplier"
          },
          {
            "key": "component"
          },
          {
            "key": "licenses"
          }
        ]
      }
    ]
  }
}
```

When applied to the test CycloneDX BOM file: `test/custom/cdx-1-6-test-metadata-has-elements.json`:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "serialNumber": "urn:uuid:1a2b3c4d-1234-abcd-9876-a3b4c5d6e7e0",
  "metadata": {
    "timestamp": "2025-08-09T07:20:00.000Z",
    "component": {
      "name": "sample app",
      "type": "application"
    },
    "licenses": [
      {
        "license": {
          "id": "Apache-2.0"
        }
      }
    ],
    "supplier": {
      "name": "Example.com",
      "url": [
        "https://example.com"
      ],
      "contact": [
        {
          "email": "info@example.com"
        }
      ]
    }
  }
}
```

and running it from the command line:

```bash
./sbom-utility validate -i test/custom/cdx-1-6-test-metadata-has-elements.json --custom test/custom/custom-metadata-has-elements.json
```

produces the following result:

```bash
[INFO] Validating 'test/custom/cdx-1-6-test-metadata-has-elements.json'...
[INFO] BOM valid against JSON schema: 'true'
[INFO] Loading custom validation config file: 'test/custom/custom-metadata-has-elements.json'...
[INFO] Validating custom action (id: `custom-test-metadata-has-elements`, selector: `{ "path": "metadata", "primaryKey": { "key": "", "value": "" } }`)...
[INFO] BOM valid against custom JSON configuration: 'test/custom/custom-metadata-has-elements.json'
```

This indicates all four properties exist in the BOM where they are expected int the `component.metadata` object (i.e., `timestamp`, `supplier`, `component` and `licenses`).

and the exit code aligns with the logged output:

```bash
$ echo $?
0
```

#### Example: Invalid: `metadata` missing `authors` element

Using the custom configuration file `test/custom/custom-metadata-element-not-found.json` for this validation check is as follows;

```json
{
  "validation": {
    "actions": [
      {
        "id": "custom-test-metadata-property-not-found",
        "description": "Test the error if metadata property is not found",
        "selector": {
          "path": "metadata"
        },
        "functions": [
          "hasProperties"
        ],
        "properties": [
          {
            "key": "authors"
          }
        ]
      }
    ]
  }
}
```

When applied to the test CycloneDX BOM file: `test/custom/cdx-1-6-test-metadata-has-elements.json` whose metadata contains many elements, but not `authors`:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "serialNumber": "urn:uuid:1a2b3c4d-1234-abcd-9876-a3b4c5d6e7e0",
  "metadata": {
    "timestamp": "2025-08-09T07:20:00.000Z",
    "component": {
      "name": "sample app",
      "type": "application"
    },
    "licenses": [
      {
        ...
      }
    ],
    "supplier": {
      ...
    }
  }
}
```

and running it from the command line:

```bash
./sbom-utility validate -i test/custom/cdx-1-6-test-metadata-has-elements.json --custom test/custom/custom-metadata-element-not-found.json
```

produces the following result:

```bash
[INFO] Validating 'test/custom/cdx-1-6-test-metadata-has-elements.json'...
[INFO] BOM valid against JSON schema: 'true'
[INFO] Loading custom validation config file: 'test/custom/custom-metadata-element-not-found.json'...
[INFO] Validating custom action (id: `custom-test-metadata-property-not-found`, selector: `{ "path": "metadata", "primaryKey": { "key": "", "value": "" } }`)...
[ERROR] invalid SBOM: custom validation failed: Function: 'hasProperties' selector: { "path": "metadata", "primaryKey": { "key": "", "value": "" } }, property: { "key": "authors", "value": "" } () (test/custom/cdx-1-6-test-metadata-has-elements.json)
[INFO] document 'test/custom/cdx-1-6-test-metadata-has-elements.json': valid=[false]
```

As expected, the exit code reflects this result:

```bash
$ echo $?
2
```

---

### Combined examples

These examples perform both a `isUnique` validation and then further inspec the unique item to validate its other properties (i.e., key-value pairs) using the `hasProperties` function.

#### Example: Verify unique disclaimer item in `metadata.properties` array and then its `value` property

Using the custom configuration file `test/custom/custom-metadata-properties-disclaimer-unique-match.json` for this validation check is as follows;

```json
{
  "validation": {
    "actions": [
      {
        "id": "custom-metadata-properties-unique-match",
        "description": "Validate BOM metadata properties has a unique disclaimer with a specific value.",
        "selector": {
          "path": "metadata.properties",
          "primaryKey": {
            "key": "name",
            "value": "urn:example.com:disclaimer"
          }
        },
        "functions": [
          "isUnique", "hasProperties"
        ],
        "properties": [
          {
            "key": "value",
            "value": "This SBOM is current as of the date it was generated and is subject to change\\."
          }
        ]
      }
    ]
  }
}
```

When applied to the same test CycloneDX BOM file that was used on the first `isUnique` example: `test/custom/cdx-1-6-test-metedata-properties-disclaimer.json`:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "timestamp": "2025-08-09T07:20:00.000Z",
    "component": {
      "type": "application",
      "name": "sample app"
    },
    "properties": [
      {
        "name": "urn:example.com:disclaimer",
        "value": "This SBOM is current as of the date it was generated and is subject to change."
      },
      {
        "name": "urn:example.com:classification",
        "value": "This SBOM is Confidential Information. Do not distribute."
      }
    ]
  }
}
```

and running it from the command line:

```bash
./sbom-utility validate -i test/custom/cdx-1-6-test-metedata-properties-disclaimer.json --custom test/custom/custom-metadata-properties-disclaimer-unique-match.json
```

produces the following result:

```bash
[INFO] Validating 'test/custom/cdx-1-6-test-metedata-properties-disclaimer.json'...
[INFO] BOM valid against JSON schema: 'true'
[INFO] Loading custom validation config file: 'test/custom/custom-metadata-properties-disclaimer-unique-match.json'...
[INFO] Validating custom action (id: `custom-metadata-properties-unique-match`, selector: `{ "path": "metadata.properties", "primaryKey": { "key": "name", "value": "urn:example.com:disclaimer" } }`)...
[INFO] >> Checking isUnique: (selector: `{metadata.properties {name urn:example.com:disclaimer}}`)...
[INFO] >> Checking hasProperties: (selector: `{metadata.properties {name urn:example.com:disclaimer}}`)...
[INFO] BOM valid against custom JSON configuration: 'test/custom/custom-metadata-properties-disclaimer-unique-match.json'
```

---

#### Example:

Using the custom configuration file `test/custom/custom-metadata-has-elements.json` for this validation check is as follows;

```json

```

When applied to the test CycloneDX BOM file: `TBD`:

```json

```

and running it from the command line:

```bash
TBD
```

produces the following result:

```bash
TBD
```

---

#### Example:

Using the custom configuration file `test/custom/custom-metadata-has-elements.json` for this validation check is as follows;

```json

```

When applied to the test CycloneDX BOM file: `TBD`:

```json

```

and running it from the command line:

```bash
TBD
```

produces the following result:

```bash
TBD
```

---