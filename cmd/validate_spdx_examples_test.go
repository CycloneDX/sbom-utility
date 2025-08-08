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

import "testing"

// SPDX - Examples
func TestValidateSpdx22Example1(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_SPDX_2_2_EXAMPLE_1)
	innerTestValidate(t, *vti)
}

func TestValidateSpdx22Example2Bin(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_SPDX_2_2_EXAMPLE_2_BIN)
	innerTestValidate(t, *vti)
}

func TestValidateSpdx22Example2Src(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_SPDX_2_2_EXAMPLE_2_SRC)
	innerTestValidate(t, *vti)
}

func TestValidateSpdx22Example5Bin(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_SPDX_2_2_EXAMPLE_5_BIN)
	innerTestValidate(t, *vti)
}

func TestValidateSpdx22Example5Src(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_SPDX_2_2_EXAMPLE_5_SRC)
	innerTestValidate(t, *vti)
}

func TestValidateSpdx22Example6Lib(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_SPDX_2_2_EXAMPLE_6_LIB)
	innerTestValidate(t, *vti)
}

func TestValidateSpdx22Example6Src(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_SPDX_2_2_EXAMPLE_6_SRC)
	innerTestValidate(t, *vti)
}

func TestValidateSpdx23MinRequired(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_SPDX_2_3_MIN_REQUIRED)
	innerTestValidate(t, *vti)
}

func TestValidateSpdx23ExamplePackage(t *testing.T) {
	vti := NewValidateTestInfoMinimum(TEST_SPDX_2_3_EXAMPLE_PACKAGE_BOM)
	innerTestValidate(t, *vti)
}

// func TestValidateSpdx23SchemaErrAddPropsNotAllowed(t *testing.T) {
// 	vti := NewValidateTestInfoMinimum(TEST_SPDX_2_3_SCHEMA_ERROR_ADD_PROPS_NOT_ALLOWED)
// 	innerTestValidate(t, *vti)
// }
