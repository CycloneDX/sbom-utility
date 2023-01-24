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
	"fmt"

	"github.com/CycloneDX/sbom-utility/utils"
	"github.com/spf13/cobra"
)

func NewCommandVersion() *cobra.Command {
	var command = new(cobra.Command)
	command.Use = CMD_VERSION
	command.Short = "Display program, binary and version information"
	command.Long = "Display program, binary and version information in SemVer format (e.g., `<project> version <x.y.z>`)"
	command.Run = func(cmd *cobra.Command, args []string) {
		getLogger().Enter()
		defer getLogger().Exit()
		fmt.Printf("%s version %s\n", utils.GlobalFlags.Project, utils.GlobalFlags.Version)
	}
	return command
}
