# Custom validation

In addition to validating the the BOM input file using the standard CycloneDX schema, you now can provide a custom JSON file that will apply a built-in set of validation functions to selected parts of the BOM document that can validate JSON elements, property keys and values.

The current set of functions that can achieve this includes:

- `isUnique` - checks uniqueness of array items given a property name as key
- `hasProperties` - can verify that a named property exists on a select element and can also enforce the corresponding property has the expected value using regex.

**Note**: *More functions are planned for future releases if use cases are found.*

---

### Usage

The minimum set of required command flags to invoke custom validation using the utility's `validate` command would be:

```bash
./sbom-utility validate -i <input-bom.json> --custom <custom-validation-config.json>
```

### Custom validation examples

#### `isUnique` - Array item uniqueness

The `isUnique` function can be used to validate that all array items in a specific property have unique values.

##### Example: Unique propery `name` in `metadata.properties` array


Using the custom configuration file `test/custom/custom-metadata-properties-disclaimer-unique.json` for this validation check is as follows;

```json
{
  "validation": {
    "actions": [
      {
        "id": "custom-metadata-properties-unique-disclaimer",
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

When applied to the test CycloneDX BOM file: `test/custom/cdx-1-6-test-metedata-properties-unique-disclaimer.json`:

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
./sbom-utility validate -i test/custom/cdx-1-6-test-metedata-properties-unique-disclaimer.json --custom test/custom/custom-metadata-properties-disclaimer-unique.json
```

produces the following result:

```bash
[INFO] Validating 'test/custom/cdx-1-6-test-metedata-properties-unique-disclaimer.json'...
[INFO] BOM valid against JSON schema: 'true'
[INFO] Loading custom validation config file: 'test/custom/custom-metadata-properties-disclaimer-unique.json'...
[INFO] Validating custom action (id: `custom-metadata-properties-unique-disclaimer`, selector: `{ "path": "metadata.properties", "primaryKey": { "key": "name", "value": "urn:example.com:disclaimer" } }`)...
[INFO] >> Checking isUnique: (selector: `{metadata.properties {name urn:example.com:disclaimer}}`)...
[INFO] BOM valid against custom JSON configuration: 'test/custom/custom-metadata-properties-disclaimer-unique.json'
```

As you can see, the standard schema validation is first applied and returns "`BOM valid against JSON schema: 'true'`" then the custom checks are applied which also returns "`BOM valid against custom JSON configuration`" with the details of each check provided..

---