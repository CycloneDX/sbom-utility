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

package utils

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/scs/sbom-utility/log"
)

func FindVerifyConfigFileAbsPath(logger *log.MiniLogger, filename string) (absFilename string, err error) {
	logger.Enter()
	defer logger.Exit()

	if len(filename) == 0 {
		err = fmt.Errorf("invalid config filename: `%s`", filename)
		return
	}

	// first, see if the config file is found at the location
	// that may have been provided via the command line argument
	if _, err = os.Stat(filename); err == nil {
		absFilename = filename
		logger.Tracef("found config file `%s` at location provided.", absFilename)
		return
	}

	// if the filename was not passed using an absolute path, attempt to find it
	// relative to the executable directory then the current working directory
	if filepath.IsAbs(filename) {
		// first, attempt to find file relative to the executable
		tmpFilename := filepath.Join(GlobalFlags.ExecDir, filename)
		logger.Tracef("Checking for config relative to executable: `%s`...", tmpFilename)
		if _, err = os.Stat(tmpFilename); err == nil {
			absFilename = tmpFilename
			logger.Tracef("found config file relative to executable: `%s`", absFilename)
			return
		}

		// Last, attempt to find the config file in the current working directory
		// Note: this is sometimes needed in IDE/test environments
		tmpFilename = filepath.Join(GlobalFlags.WorkingDir, filename)
		logger.Tracef("Checking for config relative to working directory: `%s`...", tmpFilename)
		if _, err = os.Stat(tmpFilename); err == nil {
			absFilename = tmpFilename
			logger.Tracef("found config file relative to working directory: `%s`", absFilename)
			return
		}
	}

	logger.Tracef("returning config absolute filename: `%s`", absFilename)
	return
}
