// SPDX-License-Identifier: Apache-2.0

// Package bridge provides thin wrappers that translate GUI inputs into the
// exact same function calls the CLI cobra commands use, by mutating the
// shared utils.GlobalFlags state that every cmd.* function reads from.
//
// This means the GUI always has feature parity with the CLI at zero extra cost:
// any improvement to a cmd function is automatically available in the GUI.
package bridge
