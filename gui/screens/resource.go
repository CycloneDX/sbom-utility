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

// ResourceScreen wraps the `resource list` command.
type ResourceScreen struct {
	run func() // populated by Layout; shared by button and Activate
}

func NewResourceScreen() *ResourceScreen { return &ResourceScreen{} }

// Activate executes the default resource-list command if a BOM file is loaded.
func (s *ResourceScreen) Activate() {
	if s.run != nil {
		s.run()
	}
}

func (s *ResourceScreen) Layout(_ fyne.Window, state *AppState) fyne.CanvasObject {
	results := widgets.NewResultsView()

	// ── Flags panel content ───────────────────────────────────────
	typeSelect := widget.NewSelect(
		[]string{"(all)", "component", "service"},
		nil,
	)
	typeSelect.SetSelected("(all)")

	whereEntry := widget.NewEntry()
	whereEntry.SetPlaceHolder("e.g. name=log.*")

	formatSelect := widget.NewSelect(
		[]string{"txt", "csv", "md"},
		nil,
	)
	formatSelect.SetSelected("txt")

	flagsContent := container.NewVBox(
		makeFlagRow("Resource type (--type):", typeSelect),
		makeFlagRow("Output format (--format):", formatSelect),
		makeFlagRow("Filter (--where key=regex,…):", whereEntry),
		resourceWhereHelpLabel(),
	)
	flagsPanel := widgets.NewSidePanel("Resource List Options", flagsContent, true)

	// ── File path from shared state ───────────────────────────────
	var filePath string
	state.OnBOMFileChange(func(p string) { filePath = p })

	// ── Shared run logic (button + auto-activate) ─────────────────
	s.run = func() {
		if filePath == "" {
			return
		}
		resourceType := typeSelect.Selected
		if resourceType == "(all)" {
			resourceType = ""
		}
		fyne.Do(func() { results.SetText("Scanning resources…") })
		go func() {
			out, err := bridge.ListResourcesText(bridge.ResourceParams{
				InputFile:    filePath,
				ResourceType: resourceType,
				OutputFormat: formatSelect.Selected,
				WhereRaw:     whereEntry.Text,
			})
			var text string
			if err != nil {
				text = "[ERROR] " + err.Error() + "\n\n" + out
			} else if out == "" {
				text = "(no resources found)"
			} else {
				text = out
			}
			fyne.Do(func() { results.SetText(text) })
		}()
	}

	// ── Run button ────────────────────────────────────────────────
	runBtn := widget.NewButtonWithIcon("List Resources", theme.StorageIcon(), func() {
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

func resourceWhereHelpLabel() fyne.CanvasObject {
	lbl := widget.NewLabelWithStyle(
		"Resource filter keys:\n"+
			"  resource-type, name, version, bom-ref, group, description",
		fyne.TextAlignLeading,
		fyne.TextStyle{Italic: true},
	)
	lbl.Wrapping = fyne.TextWrapWord
	return lbl
}
