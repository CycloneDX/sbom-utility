// SPDX-License-Identifier: Apache-2.0

package screens

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/CycloneDX/sbom-utility/gui/bridge"
	"github.com/CycloneDX/sbom-utility/gui/widgets"
)

// LicenseScreen wraps the `license list` command.
type LicenseScreen struct {
	run func() // populated by Layout; shared by button and Activate
}

func NewLicenseScreen() *LicenseScreen { return &LicenseScreen{} }

// Activate executes the default license-list command if a BOM file is loaded.
func (s *LicenseScreen) Activate() {
	if s.run != nil {
		s.run()
	}
}

func (s *LicenseScreen) Layout(_ fyne.Window, state *AppState) fyne.CanvasObject {
	results := widgets.NewResultsView()

	// ── Flags panel content ───────────────────────────────────────
	summaryCheck := widget.NewCheck("Summary mode (--summary)", nil)

	whereEntry := widget.NewEntry()
	whereEntry.SetPlaceHolder("e.g. usage-policy=allow,license=MIT")

	formatSelect := widget.NewSelect(
		[]string{"txt", "csv", "json", "md"},
		nil,
	)
	formatSelect.SetSelected("txt")

	flagsContent := container.NewVBox(
		summaryCheck,
		makeFlagRow("Output format (--format):", formatSelect),
		makeFlagRow("Filter (--where key=regex,…):", whereEntry),
		whereHelpLabel(),
	)
	flagsPanel := widgets.NewSidePanel("License List Options", flagsContent, true)

	// ── File path from shared state ───────────────────────────────
	var filePath string
	state.OnBOMFileChange(func(p string) { filePath = p })

	// ── Shared run logic (button + auto-activate) ─────────────────
	s.run = func() {
		if filePath == "" {
			return
		}
		fyne.Do(func() { results.SetText("Scanning licenses…") })
		go func() {
			out, err := bridge.ListLicensesText(bridge.LicenseParams{
				InputFile:    filePath,
				Summary:      summaryCheck.Checked,
				OutputFormat: formatSelect.Selected,
				WhereRaw:     whereEntry.Text,
			})
			var text string
			if err != nil {
				text = "[ERROR] " + err.Error() + "\n\n" + out
			} else if out == "" {
				text = "(no licenses found)"
			} else {
				text = out
			}
			fyne.Do(func() { results.SetText(text) })
		}()
	}

	// ── Run button ────────────────────────────────────────────────
	runBtn := widget.NewButtonWithIcon("List Licenses", theme.InfoIcon(), func() {
		if filePath == "" {
			results.SetText("[ERROR] No BOM file loaded.")
			return
		}
		s.run()
	})
	runBtn.Importance = widget.HighImportance

	topBar := container.NewBorder(nil, nil, nil, runBtn, nil)
	split := container.NewHSplit(
		container.NewVScroll(flagsPanel.CanvasObject()),
		results.CanvasObject(),
	)
	split.SetOffset(0.28)

	return container.NewBorder(
		container.NewVBox(topBar, widget.NewSeparator()),
		nil, nil, nil,
		split,
	)
}

// whereHelpLabel builds a small italicised hint explaining --where syntax.
func whereHelpLabel() fyne.CanvasObject {
	lbl := widget.NewLabelWithStyle(
		"Filter syntax: key=regex  (comma-separated for multiple clauses)\n"+
			"License keys: usage-policy, license-type, license, resource-name,\n"+
			"  bom-ref, bom-location, purl",
		fyne.TextAlignLeading,
		fyne.TextStyle{Italic: true},
	)
	lbl.Wrapping = fyne.TextWrapWord
	return lbl
}
