// SPDX-License-Identifier: Apache-2.0
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
package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/CycloneDX/sbom-utility/utils"
)

const (
	// Patch operations
	IETF_RFC6902_OP_ADD     = "add"
	IETF_RFC6902_OP_REMOVE  = "remove"
	IETF_RFC6902_OP_REPLACE = "replace"
	IETF_RFC6902_OP_MOVE    = "move"
	IETF_RFC6902_OP_COPY    = "copy"
	IETF_RFC6902_OP_TEST    = "test"
)

type IETF6902Document struct {
	filename    string
	absFilename string
	rawBytes    []byte
	Records     []IETF6902Record
}

// Example of all opcodes:
//
//	{ "op": "test", "path": "/a/b/c", "value": "foo" },
//	{ "op": "remove", "path": "/a/b/c" },
//	{ "op": "add", "path": "/a/b/c", "value": [ "foo", "bar" ] },
//	{ "op": "replace", "path": "/a/b/c", "value": 42 },
//	{ "op": "move", "from": "/a/b/c", "path": "/a/b/d" },
//	{ "op": "copy", "from": "/a/b/d", "path": "/a/b/e" }
type IETF6902Record struct {
	Operation string      `json:"op"`
	Path      string      `json:"path"`
	Value     interface{} `json:"value,omitempty"`
	From      string      `json:"from,omitempty"`
}

func NewIETFRFC6902PatchDocument(patchFilename string) (document *IETF6902Document) {
	temp := IETF6902Document{
		filename: patchFilename,
	}
	return &temp
}

func (document *IETF6902Document) ReadRawBytes() (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// only read once
	if document.rawBytes == nil {
		// validate filename
		if len(document.filename) == 0 {
			return fmt.Errorf("schema: invalid filename: `%s`", document.filename)
		}

		// Conditionally append working directory if no abs. path detected
		if len(document.filename) > 0 && !filepath.IsAbs(document.filename) {
			document.absFilename = filepath.Join(utils.GlobalFlags.WorkingDir, document.filename)
		} else {
			document.absFilename = document.filename
		}

		// Open our jsonFile
		jsonFile, errOpen := os.Open(document.absFilename)

		// if input file cannot be opened, log it and terminate
		if errOpen != nil {
			err = errOpen
			getLogger().Error(err)
			return
		}

		// defer the closing of our jsonFile
		defer jsonFile.Close()

		// read our opened jsonFile as a byte array.
		document.rawBytes, err = io.ReadAll(jsonFile)
		if err != nil {
			getLogger().Error(err)
			return
		}

		getLogger().Tracef("read data from: `%s`", document.filename)
		getLogger().Tracef("\n  >> rawBytes[:100]=[%s]", document.rawBytes[:100])
	}
	return
}

func (document *IETF6902Document) UnmarshalRecords() (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// Read in the bytes of the patch file
	if err = document.ReadRawBytes(); err != nil {
		return
	}

	// optimistically, prepare the receiving structure and unmarshal
	err = json.Unmarshal(document.rawBytes, &document.Records)

	if err != nil {
		getLogger().Warningf("unmarshal failed: %v", err)
		return
	}

	return
}
