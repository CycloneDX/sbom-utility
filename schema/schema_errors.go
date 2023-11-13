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

package schema

import "fmt"

// Format/schema error types
type UnsupportedFormatError struct {
	Type      string
	Message   string
	InputFile string
	Format    string
	Version   string
	Variant   string
	Command   string
	Flags     string
}

type UnsupportedSchemaError struct {
	UnsupportedFormatError
}

func NewUnsupportedSchemaError(m string, format string, version string, variant string) *UnsupportedSchemaError {
	var err = new(UnsupportedSchemaError)
	err.Type = ERR_TYPE_UNSUPPORTED_SCHEMA
	err.Message = m
	err.Format = format
	err.Version = version
	err.Variant = variant
	return err
}

func NewUnsupportedFormatError(msg string, f string, fmt string, cmd string, flags string) *UnsupportedFormatError {
	var err = new(UnsupportedFormatError)
	err.Type = ERR_TYPE_UNSUPPORTED_FORMAT
	err.Message = msg
	err.InputFile = f
	err.Format = fmt
	err.Command = cmd
	err.Flags = flags
	return err
}

func NewUnsupportedFormatForCommandError(f string, fmt string, cmd string, flags string) *UnsupportedFormatError {
	var err = new(UnsupportedFormatError)
	err.Type = ERR_TYPE_UNSUPPORTED_FORMAT
	err.Message = MSG_FORMAT_UNSUPPORTED_COMMAND
	err.InputFile = f
	err.Format = fmt
	err.Command = cmd
	err.Flags = flags
	return err
}

func NewUnknownFormatError(f string) *UnsupportedFormatError {
	var err = new(UnsupportedFormatError)
	err.Type = ERR_TYPE_UNSUPPORTED_FORMAT
	err.Message = MSG_FORMAT_UNSUPPORTED_UNKNOWN
	err.InputFile = f
	return err
}

func (err UnsupportedFormatError) Error() string {
	baseMessage := fmt.Sprintf("%s: %s (`%s`)", err.Type, err.Message, err.InputFile)
	if err.Format != "" {
		return fmt.Sprintf("%s: format: `%s`, command: `%s`, flags: `%s`",
			baseMessage,
			err.Format,
			err.Command,
			err.Flags)
	}
	return baseMessage
}

func (err UnsupportedSchemaError) Error() string {
	return fmt.Sprintf("%s: %s: Schema Format: `%s`, Version: `%s`, Variant: `%s` ",
		err.Type,
		err.Message,
		err.Format,
		err.Version,
		err.Variant)
}
