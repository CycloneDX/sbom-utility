// SPDX-License-Identifier: Apache-2.0

package bridge

import (
	"github.com/CycloneDX/sbom-utility/cmd"
	"github.com/CycloneDX/sbom-utility/utils"
)

// BOMInfo holds the metadata extracted when a BOM file is first loaded.
type BOMInfo struct {
	// SpecVersion is the CycloneDX specVersion declared in the BOM
	// (e.g. "1.5").  Empty if detection failed.
	SpecVersion string
	// Format is the canonical format name (e.g. "CycloneDX").
	Format string
	// FilePath is the absolute path of the loaded BOM file.
	FilePath string
}

// LoadBOMInfo parses the BOM file at filePath just enough to detect its
// format and schema version.  It is safe to call from a goroutine.
func LoadBOMInfo(filePath string) BOMInfo {
	utils.GlobalFlags.PersistentFlags.InputFile = filePath
	doc, err := cmd.LoadInputBOMFileAndDetectSchema()
	if err != nil || doc == nil {
		return BOMInfo{FilePath: filePath}
	}
	return BOMInfo{
		SpecVersion: doc.SchemaInfo.Version,
		Format:      doc.FormatInfo.CanonicalName,
		FilePath:    filePath,
	}
}
