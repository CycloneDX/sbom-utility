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
- [Combined examples](#combined-examples) - shows how to combine the `isUnique` function with the `hasProperties` function on the same selected JSON array.
- [Additional use cases](#additional-use-cases) - additional, real-world use cases.

---

### `isUnique` examples

The `isUnique` function can be used to validate that an item in a JSON array is "unique" using a specified `primaryKey` property. The `primaryKey` property specifies the JSON map `key` used as the *primary key* for for items in the array and its `value` tested for uniqueness.

#### Example: Valid: `property` is unique in the BOM's `properties` array

The custom validation configuration file `test/custom/config-cdx-bom-properties-unique.json` with contents::

```json
{
  "validation": {
    "actions": [
      {
        "id": "custom-bom-properties-unique",
        "description": "Validate BOM properties unique",
        "selector": {
          "path": "properties",
          "primaryKey": {
            "key": "name",
            "value": "yyz"
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

provides a `path` value as part of the `selector` object which is used to locate the BOM's top-level `properties` array which contains the `property` items that will be validated for uniqueness.

As each item of the selected JSON array is itself a JSON map object, the `primaryKey` of the `selector` is used to identify the map `key` (i.e., `name` in this case) and specified `value` (i.e., `yyz`) for to test for uniqueness within the array.

When this example's custom validation configuration is applied to the test CycloneDX BOM file: `test/custom/cdx-1-6-test-bom-properties.json` with contents:

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
      "name": "yyz",
      "value": "rush"
    },
    {
      "name": "foo",
      "value": "bar1"
    },
    {
      "name": "foo",
      "value": "bar2"
    }
  ]
}
```

by running it from the command line:

```bash
./sbom-utility validate -i test/custom/cdx-1-6-test-bom-properties.json --custom test/custom/config-cdx-bom-properties-unique.json
```

produces the following result:

```bash
[INFO] Validating 'test/custom/cdx-1-6-test-bom-properties.json'...
[INFO] BOM valid against JSON schema: 'true'
[INFO] Loading custom validation config file: 'test/custom/config-cdx-bom-properties-unique.json'...
[INFO] Validating custom action (id: `custom-bom-properties-unique`, selector: `{ "path": "properties", "primaryKey": { "key": "name", "value": "yyz" } }`)...
[INFO] >> Checking isUnique: (selector: `{ "path": "properties", "primaryKey": { "key": "name", "value": "yyz" } }`)...
[INFO] BOM valid against custom JSON configuration: 'test/custom/config-cdx-bom-properties-unique.json': 'true'
```

As you can see, the standard schema validation is first applied and returns "`BOM valid against JSON schema: 'true'`" then the custom checks are applied which also returns "`BOM valid against custom JSON configuration`: `true`" with the details of each check provided.

The `validate` command factors in the custom validation along with the normal schema validation when setting the exit code (i.e., `0`, zero in this valid case).  This preserves the ability to test exit code from the command line and within test scripts:

```
$ echo $?
0
```

---

#### Example: Invalid: `property` item is not unique in BOM `properties` array

Using the custom validation configuration file `test/custom/config-cdx-bom-properties-not-unique.json` with contents::

```json
{
  "validation": {
    "actions": [
      {
        "id": "custom-bom-properties-not-unique",
        "description": "Validate BOM properties not unique",
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

and applying it to the test CycloneDX BOM file: `test/custom/cdx-1-6-test-bom-properties.json`:

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
      "name": "yyz",
      "value": "rush"
    },
    {
      "name": "foo",
      "value": "bar1"
    },
    {
      "name": "foo",
      "value": "bar2"
    }
  ]
}
```

by running it from the command line:

```bash
./sbom-utility validate -i test/custom/cdx-1-6-test-bom-properties.json --custom test/custom/config-cdx-bom-properties-not-unique.json
```

produces the following result:

```bash
[INFO] Validating 'test/custom/cdx-1-6-test-bom-properties.json'...
[INFO] BOM valid against JSON schema: 'true'
[INFO] Loading custom validation config file: 'test/custom/config-cdx-bom-properties-not-unique.json'...
[INFO] Validating custom action (id: `custom-bom-properties-not-unique`, selector: `{ "path": "properties", "primaryKey": { "key": "name", "value": "foo" } }`)...
[INFO] >> Checking isUnique: (selector: `{ "path": "properties", "primaryKey": { "key": "name", "value": "foo" } }`)...
[INFO] BOM valid against custom JSON configuration: 'test/custom/config-cdx-bom-properties-not-unique.json': 'false'
[ERROR] invalid SBOM: custom validation failed: Function: 'isUnique', selector: { "path": "properties", "primaryKey": { "key": "name", "value": "foo" } }, matches found: 2, bom: (test/custom/cdx-1-6-test-bom-properties.json)
[INFO] document 'test/custom/cdx-1-6-test-bom-properties.json': valid=[false]
```

which indicates the `property` designated as the "primary key" (i.e., the `name` key with value `foo`) resulted in multiple (i.e., two (2)) items and therefore not unique.

In other words, there were two CycloneDX `property` items in the array that have the `foo` value in the `name` key which was designated as the `primaryKey`.

In this invalid example, the exit code will reflect the custom validation failure with a non-zero exit code:

```bash
echo $?
2
```

---

### `hasProperties` examples

The `hasProperties` function can be used to validate that specific properties (i.e., key-value pairs) are present in a selected object within the BOM document.

#### Example: Valid: `metadata` has `timestamp`, `supplier`, `component` and `licenses` properties

Using the custom validation configuration file `test/custom/config-cdx-metadata-elements-found.json` with contents::

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

and applying it to the test CycloneDX BOM file: `test/custom/cdx-1-6-test-bom-metadata.json`:

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

by running it from the command line:

```bash
./sbom-utility validate -i test/custom/cdx-1-6-test-bom-metadata.json --custom test/custom/config-cdx-metadata-elements-found.json
```

produces the following result:

```bash
[INFO] Validating 'test/custom/cdx-1-6-test-bom-metadata.json'...
[INFO] BOM valid against JSON schema: 'true'
[INFO] Loading custom validation config file: 'test/custom/config-cdx-metadata-elements-found.json'...
[INFO] Validating custom action (id: `custom-metadata-elements-found`, selector: `{ "path": "metadata", "primaryKey": { "key": "", "value": "" } }`)...
[INFO] >> Checking hasProperties: (selector: `{ "path": "metadata", "primaryKey": { "key": "", "value": "" } }`)...
[INFO] BOM valid against custom JSON configuration: 'test/custom/config-cdx-metadata-elements-found.json': 'true'
```

This indicates all four properties exist in the BOM where they are expected in the BOM `metadata` object (i.e., `timestamp`, `supplier`, `component` and `licenses`).

and the exit code aligns with the logged output:

```bash
$ echo $?
0
```

#### Example: Invalid: `metadata` missing `authors` element

Using the custom validation configuration file `test/custom/config-cdx-metadata-elements-not-found.json` with contents::

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

and applying it to the test CycloneDX BOM file: `test/custom/cdx-1-6-test-bom-metadata.json` whose metadata contains many elements, but not `authors`:

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

by running it from the command line:

```bash
./sbom-utility validate -i test/custom/cdx-1-6-test-bom-metadata.json --custom test/custom/config-cdx-metadata-elements-not-found.json
```

produces the following error result since no `authors` property was found:

```bash
[INFO] Validating 'test/custom/cdx-1-6-test-bom-metadata.json'...
[INFO] BOM valid against JSON schema: 'true'
[INFO] Loading custom validation config file: 'test/custom/config-cdx-metadata-elements-not-found.json'...
[INFO] Validating custom action (id: `custom-metadata-elements-not-found`, selector: `{ "path": "metadata", "primaryKey": { "key": "", "value": "" } }`)...
[INFO] >> Checking hasProperties: (selector: `{ "path": "metadata", "primaryKey": { "key": "", "value": "" } }`)...
[INFO] BOM valid against custom JSON configuration: 'test/custom/config-cdx-metadata-elements-not-found.json': 'false'
[ERROR] invalid SBOM: custom validation failed: Function: 'hasProperties' selector: { "path": "metadata", "primaryKey": { "key": "", "value": "" } }, property: { "key": "authors", "value": "" }, bom: (test/custom/cdx-1-6-test-bom-metadata.json)
[INFO] document 'test/custom/cdx-1-6-test-bom-metadata.json': valid=[false]
```

As expected, the exit code reflects the failed result:

```bash
$ echo $?
2
```

---

### Combined examples

These examples perform both a `isUnique` validation and then further inspec the unique item to validate its other properties (i.e., key-value pairs) using the `hasProperties` function.

---

## Additional use cases

This section shows some additional use cases that are based on real-world requirements.

#### BOM Disclaimer and Classification

The BOM `metadata` has a `properties` array that allows organizations to add their own custom, property key-value pairs for legal and or classification purposes and validate for them.

##### Example: Validate "disclaimer" `property` with `name` key is unique in the `metadata.properties` array

Using the custom validation configuration file `test/custom/config-cdx-metadata-properties-disclaimer-unique.json` with contents::

```json
{
  "validation": {
    "actions": [
      {
        "id": "custom-metadata-properties-disclaimer-unique",
        "description": "Validate BOM metadata properties has a unique disclaimer value.",
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

The `path` value of the `selector` object is set to `metadata.properties` and will be used to locate the JSON array that holds the `property` items.  As each item is a JSON map object, the `primaryKey` can be used to identify the map `key` (in this case the `name` map key) and its `value` (i.e., `urn:example.com:disclaimer`) used to identify the specific key value to validate as unique within the array.

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
        "value": "This SBOM is current as of date of the software component's release."
      },
      {
        "name": "urn:example.com:classification",
        "value": "This SBOM is Confidential Information. Do not distribute."
      }
    ]
  }
}
```

by running it from the command line:

```bash
./sbom-utility validate -i test/custom/cdx-1-6-test-metedata-properties-disclaimer.json --custom test/custom/config-cdx-metadata-properties-disclaimer-unique.json
```

it produces the following result:

```bash
[INFO] Validating 'test/custom/cdx-1-6-test-metedata-properties-disclaimer.json'...
[INFO] BOM valid against JSON schema: 'true'
[INFO] Loading custom validation config file: 'test/custom/config-cdx-metadata-properties-disclaimer-unique.json'...
[INFO] Validating custom action (id: `custom-metadata-properties-disclaimer-unique`, selector: `{ "path": "metadata.properties", "primaryKey": { "key": "name", "value": "urn:example.com:disclaimer" } }`)...
[INFO] >> Checking isUnique: (selector: `{ "path": "metadata.properties", "primaryKey": { "key": "name", "value": "urn:example.com:disclaimer" } }`)...
[INFO] BOM valid against custom JSON configuration: 'test/custom/config-cdx-metadata-properties-disclaimer-unique.json': 'true'
```

As you can see, the standard schema validation is first applied and returns "`BOM valid against JSON schema: 'true'`" then the custom checks are applied which also returns "`BOM valid against custom JSON configuration`" with the details of each check provided.

The `validate` command factors in the custom validation along with the normal schema validation when setting the exit code (i.e., `0`, zero in this valid case).  This preserves the ability to test exit code from the command line and within test scripts:

```
$ echo $?
0
```

---

##### Example: unique `disclaimer` and `value` property matches

This example builds upon the last example additionally validate that the unique property with `name` key equal to `urn:example.com:disclaimer` also has a `value` that matches a specific value.

Using the custom validation configuration file `test/custom/config-cdx-metadata-properties-disclaimer-unique-match.json` with contents::

```json
{
  "validation": {
    "actions": [
      {
        "id": "custom-metadata-properties-disclaimer-unique-match",
        "description": "Validate BOM metadata properties has a unique disclaimer property and specified value.",
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
            "value": "This SBOM is current as of the date it was generated and is subject to change."
          }
        ]
      }
    ]
  }
}
```

and applying it to the test CycloneDX BOM file: `test/custom/cdx-1-6-test-metedata-properties-disclaimer.json`:

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

by running it from the command line:

```bash
./sbom-utility validate -i test/custom/cdx-1-6-test-metedata-properties-disclaimer.json --custom test/custom/config-cdx-metadata-properties-disclaimer-unique-match.json
```

produces the following result:

```bash
[INFO] Validating 'test/custom/cdx-1-6-test-metedata-properties-disclaimer.json'...
[INFO] BOM valid against JSON schema: 'true'
[INFO] Loading custom validation config file: 'test/custom/config-cdx-metadata-properties-disclaimer-unique-match.json'...
[INFO] Validating custom action (id: `custom-metadata-properties-disclaimer-unique-match`, selector: `{ "path": "metadata.properties", "primaryKey": { "key": "name", "value": "urn:example.com:disclaimer" } }`)...
[INFO] >> Checking isUnique: (selector: `{ "path": "metadata.properties", "primaryKey": { "key": "name", "value": "urn:example.com:disclaimer" } }`)...
[INFO] >> Checking hasProperties: (selector: `{ "path": "metadata.properties", "primaryKey": { "key": "name", "value": "urn:example.com:disclaimer" } }`)...
[INFO] BOM valid against custom JSON configuration: 'test/custom/config-cdx-metadata-properties-disclaimer-unique-match.json': 'true'
```

<!-- #### Example:

Using the custom validation configuration file `TBD` with contents::

```json

```

and applying it to the test CycloneDX BOM file: `TBD`:

```json

```

by running it from the command line:

```bash
TBD
```

produces the following result:

```bash
TBD
``` -->