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

import "testing"

const (
	// SPDX - Examples
	TEST_SPDX_2_2_EXAMPLE_1     = "examples/spdx/example1/example1.json"
	TEST_SPDX_2_2_EXAMPLE_2_BIN = "examples/spdx/example2/example2-bin.json"
	TEST_SPDX_2_2_EXAMPLE_2_SRC = "examples/spdx/example2/example2-src.json"
	TEST_SPDX_2_2_EXAMPLE_5_BIN = "examples/spdx/example5/example5-bin.json"
	TEST_SPDX_2_2_EXAMPLE_5_SRC = "examples/spdx/example5/example5-src.json"
	TEST_SPDX_2_2_EXAMPLE_6_LIB = "examples/spdx/example6/example6-lib.json"
	TEST_SPDX_2_2_EXAMPLE_6_SRC = "examples/spdx/example6/example6-src.json"
)

// SPDX - Examples
func TestValidateSpdx22Example1(t *testing.T) {
	//innerValidateError(t, TEST_SPDX_2_2_EXAMPLE_1, SCHEMA_VARIANT_NONE, FORMAT_TEXT, nil)
	vti := NewValidateTestInfoMinimum(TEST_SPDX_2_2_EXAMPLE_1)
	innerValidateTest(t, *vti)
}

func TestValidateSpdx22Example2Bin(t *testing.T) {
	//innerValidateError(t, TEST_SPDX_2_2_EXAMPLE_2_BIN, SCHEMA_VARIANT_NONE, FORMAT_TEXT, nil)
	vti := NewValidateTestInfoMinimum(TEST_SPDX_2_2_EXAMPLE_2_BIN)
	innerValidateTest(t, *vti)
}

func TestValidateSpdx22Example2Src(t *testing.T) {
	//innerValidateError(t, TEST_SPDX_2_2_EXAMPLE_2_SRC, SCHEMA_VARIANT_NONE, FORMAT_TEXT, nil)
	vti := NewValidateTestInfoMinimum(TEST_SPDX_2_2_EXAMPLE_2_SRC)
	innerValidateTest(t, *vti)
}

func TestValidateSpdx22Example5Bin(t *testing.T) {
	//innerValidateError(t, TEST_SPDX_2_2_EXAMPLE_5_BIN, SCHEMA_VARIANT_NONE, FORMAT_TEXT, nil)
	vti := NewValidateTestInfoMinimum(TEST_SPDX_2_2_EXAMPLE_5_BIN)
	innerValidateTest(t, *vti)
}

func TestValidateSpdx22Example5Src(t *testing.T) {
	//innerValidateError(t, TEST_SPDX_2_2_EXAMPLE_5_SRC, SCHEMA_VARIANT_NONE, FORMAT_TEXT, nil)
	vti := NewValidateTestInfoMinimum(TEST_SPDX_2_2_EXAMPLE_5_SRC)
	innerValidateTest(t, *vti)
}

func TestValidateSpdx22Example6Lib(t *testing.T) {
	//innerValidateError(t, TEST_SPDX_2_2_EXAMPLE_6_LIB, SCHEMA_VARIANT_NONE, FORMAT_TEXT, nil)
	vti := NewValidateTestInfoMinimum(TEST_SPDX_2_2_EXAMPLE_6_LIB)
	innerValidateTest(t, *vti)
}

func TestValidateSpdx22Example6Src(t *testing.T) {
	//innerValidateError(t, TEST_SPDX_2_2_EXAMPLE_6_SRC, SCHEMA_VARIANT_NONE, FORMAT_TEXT, nil)
	vti := NewValidateTestInfoMinimum(TEST_SPDX_2_2_EXAMPLE_6_SRC)
	innerValidateTest(t, *vti)
}
