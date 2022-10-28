Note: did not record any changes that include:
- any  changes "description" fields (including addition of a "description" field where one did not exist in the previous version)
- any changes in order that do not affect data changes (e.g., "enum" ordering, property "required" ordering, etc.)

| Field | Type | 2.3 Change | Description/Notes |
| --- | --- | --- | --- |
|'creationInfo" | Add required field |```"required": [..., "creators"],```||
|"files" (items) -> "licenseInfoInFiles"|Removed constraint|removed constraint:```"minItems": 1,```||
|"files" (items) -> "licenseConcluded"|Removed object "licenseConcluded" from "required" data|removed ""licenseConcluded" from "required" data.|This may be a response to the fact not all files have (concluded) licenses?|
|"builtDate"|Added field "builtDate"|```"builtDate": { "description": "...","type": "string"},```|This field provides a place for recording the actual date the package was built."|
|"externalRefs"->"referenceCategory"|Added "PERSISTENT_ID" to enum|```"enum": [...,"PERSISTENT_ID",],```||
|"packages" (items) -> "primaryPackagePurpose"|Added object "primaryPackagePurpose"|```"primaryPackagePurpose": { "description": "...", "type": "object" },```|Package Purpose is intrinsic to how the package is being used rather than the content of the package.|
|"packages" (items) -> "releaseDate"|Added field "releaseDate"|```"releaseDate": { "description": "...", "type": "string" },```|This field provides a place for recording the date the package was released.|
|"packages" (items) -> "validUntilDate"|Added field "validUntilDate"|```"validUntilDate": { "description": "...", "type": "string" },```||
|"files" (items) |Removed required properties|removed: ```"licenseConcluded","copyrightText"```||
|"files" (items)|Added required properties|added: ```"checksums"```||
|"packages" (items)|Removed required properties|removed:```"licenseConcluded", "licenseDeclared", "copyrightText"```||
|"relationships" -> "relationshipType"|enum value added:"AMENDS"|added:```"AMENDS"```||
|"snippets" (items)|Removed required properties|removed:```"licenseConcluded"```||
