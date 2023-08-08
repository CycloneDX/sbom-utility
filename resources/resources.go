/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package resources

import (
	"embed"
)

// Embed the JSON schema files used to validate BOMs

//go:embed schema
var BOMSchemaFiles embed.FS

//go:embed config
var ConfigFiles embed.FS

const RESOURCES_SCHEMA_DIR = "schema/"
const RESOURCES_CONFIG_DIR = "config/"

func LoadConfigFile(baseFilename string) (bData []byte, err error) {
	bData, err = ConfigFiles.ReadFile(RESOURCES_CONFIG_DIR + baseFilename)
	return
}

func LoadSchemaFile(baseFilename string) (bData []byte, err error) {
	bData, err = ConfigFiles.ReadFile(RESOURCES_SCHEMA_DIR + baseFilename)
	return
}
