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

	// ── File path from shared state ───────────────────────────────
	var filePath string
	state.OnBOMFileChange(func(p string) { filePath = p })

	// ── Flags panel content ───────────────────────────────────────

	// ── Run button (lives in options panel; enabled when options change) ──
	runBtn := widget.NewButtonWithIcon("List Resources", theme.StorageIcon(), nil)
	runBtn.Importance = widget.HighImportance
	runBtn.Disable()

	markDirty := func() { runBtn.Enable() }

	typeSelect := widget.NewSelect(
		[]string{"(all)", "component", "service"},
		func(_ string) { markDirty() },
	)
	typeSelect.SetSelected("(all)")

	whereEntry := widget.NewEntry()
	whereEntry.SetPlaceHolder("e.g. name=log.*")
	whereEntry.OnChanged = func(_ string) { markDirty() }

	formatSelect := widget.NewSelect(
		[]string{"txt", "csv", "md"},
		func(f string) {
			results.SetMarkdownMode(f == "md")
			markDirty()
		},
	)
	formatSelect.SetSelected("txt")

	flagsContent := container.NewVBox(
		makeFlagRow("Resource type (--type):", typeSelect),
		makeFlagRow("Output format (--format):", formatSelect),
		makeFlagRow("Filter (--where key=regex,…):", whereEntry),
		resourceWhereHelpLabel(),
		widget.NewSeparator(),
		runBtn,
	)
	flagsPanel := widgets.NewSidePanel("Resource List Options", flagsContent, true)

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
			fyne.Do(func() {
				results.SetText(text)
				runBtn.Disable()
			})
		}()
	}

	runBtn.OnTapped = func() {
		if filePath == "" {
			results.SetText("[ERROR] No BOM file loaded.")
			return
		}
		s.run()
	}

	split := container.NewHSplit(
		container.NewVScroll(flagsPanel.CanvasObject()),
		results.CanvasObject(),
	)
	split.SetOffset(0.28)

	return container.NewBorder(
		widget.NewSeparator(),
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
