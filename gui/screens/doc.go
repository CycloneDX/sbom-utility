// SPDX-License-Identifier: Apache-2.0

// Package screens provides one Screen value per command tab in the SBOM Utility GUI.
//
// Each Screen follows the same structural pattern:
//   1. A top bar with a FilePicker for the input BOM file.
//   2. A collapsible SidePanel on the left containing command-specific flags/filters.
//   3. A Run button that invokes the bridge layer on a goroutine to keep the UI responsive.
//   4. A ResultsView filling the remaining space for tabular or text output.
package screens
