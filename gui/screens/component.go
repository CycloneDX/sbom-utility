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

// ComponentScreen wraps the `component list` command.
type ComponentScreen struct {
	run func() // populated by Layout; shared by button and Activate
}

func NewComponentScreen() *ComponentScreen { return &ComponentScreen{} }

// Activate executes the default component-list command if a BOM file is loaded.
func (s *ComponentScreen) Activate() {
	if s.run != nil {
		s.run()
	}
}

func (s *ComponentScreen) Layout(_ fyne.Window, state *AppState) fyne.CanvasObject {
	results := widgets.NewResultsView()

	// ── Flags panel content ───────────────────────────────────────
	summaryCheck := widget.NewCheck("Summary mode (--summary)", nil)

	whereEntry := widget.NewEntry()
	whereEntry.SetPlaceHolder("e.g. type=library,name=log.*")

	formatSelect := widget.NewSelect(
		[]string{"txt", "csv", "md"},
		nil,
	)
	formatSelect.SetSelected("txt")

	flagsContent := container.NewVBox(
		summaryCheck,
		makeFlagRow("Output format (--format):", formatSelect),
		makeFlagRow("Filter (--where key=regex,…):", whereEntry),
		componentWhereHelpLabel(),
	)
	flagsPanel := widgets.NewSidePanel("Component List Options", flagsContent, true)

	// ── File path from shared state ───────────────────────────────
	var filePath string
	state.OnBOMFileChange(func(p string) { filePath = p })

	// ── Shared run logic (button + auto-activate) ─────────────────
	s.run = func() {
		if filePath == "" {
			return
		}
		fyne.Do(func() { results.SetText("Scanning components…") })
		go func() {
			out, err := bridge.ListComponentsText(bridge.ComponentParams{
				InputFile:    filePath,
				Summary:      summaryCheck.Checked,
				OutputFormat: formatSelect.Selected,
				WhereRaw:     whereEntry.Text,
			})
			var text string
			if err != nil {
				text = "[ERROR] " + err.Error() + "\n\n" + out
			} else if out == "" {
				text = "(no components found)"
			} else {
				text = out
			}
			fyne.Do(func() { results.SetText(text) })
		}()
	}

	// ── Run button ────────────────────────────────────────────────
	runBtn := widget.NewButtonWithIcon("List Components", theme.ListIcon(), func() {
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

func componentWhereHelpLabel() fyne.CanvasObject {
	lbl := widget.NewLabelWithStyle(
		"Component filter keys:\n"+
			"  bom-ref, group, type, name, version, description,\n"+
			"  copyright, purl, cpe, supplier-name, manufacturer-name,\n"+
			"  publisher, number-licenses, number-hashes, scope",
		fyne.TextAlignLeading,
		fyne.TextStyle{Italic: true},
	)
	lbl.Wrapping = fyne.TextWrapWord
	return lbl
}
