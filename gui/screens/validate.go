// SPDX-License-Identifier: Apache-2.0

package screens

import (
	"fmt"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"image/color"

	"github.com/CycloneDX/sbom-utility/cmd"
	"github.com/CycloneDX/sbom-utility/gui/bridge"
	"github.com/CycloneDX/sbom-utility/gui/widgets"
)

// ValidateScreen shows the validate command's controls and results.
type ValidateScreen struct {
	run func() // populated by Layout; shared by button and Activate
}

// NewValidateScreen allocates a ValidateScreen.
func NewValidateScreen() *ValidateScreen {
	return &ValidateScreen{}
}

// Activate executes the validate command if a BOM file is loaded.
func (s *ValidateScreen) Activate() {
	if s.run != nil {
		s.run()
	}
}

// Layout constructs and returns the full screen CanvasObject.
// w is the parent window, required by the file-open dialog.
// state is the shared application state (BOM file path, etc.).
func (s *ValidateScreen) Layout(w fyne.Window, state *AppState) fyne.CanvasObject {
	// ── Results area ─────────────────────────────────────────────
	results := widgets.NewResultsView()

	// ── Status badge ─────────────────────────────────────────────
	statusLabel := widget.NewLabel("")
	statusLabel.TextStyle = fyne.TextStyle{Bold: true}
	statusRect := canvas.NewRectangle(color.Transparent)
	statusRect.SetMinSize(fyne.NewSize(16, 16))
	statusRow := container.NewHBox(statusRect, statusLabel)

	setStatus := func(valid bool, errText string) {
		if valid {
			statusRect.FillColor = color.NRGBA{R: 34, G: 139, B: 34, A: 255} // forest green
			statusLabel.SetText("VALID")
		} else {
			statusRect.FillColor = color.NRGBA{R: 200, G: 30, B: 30, A: 255} // red
			if errText != "" {
				statusLabel.SetText("INVALID — " + errText)
			} else {
				statusLabel.SetText("INVALID")
			}
		}
		statusRect.Refresh()
	}

	// ── Flag controls (collapsible panel content) ─────────────────
	variantEntry := widget.NewEntry()
	variantEntry.SetPlaceHolder("e.g. strict  (blank = auto)")

	forceSchemaEntry := widget.NewEntry()
	forceSchemaEntry.SetPlaceHolder("path/to/schema.json  (blank = auto)")

	maxErrorsEntry := widget.NewEntry()
	maxErrorsEntry.SetText(fmt.Sprintf("%d", cmd.DEFAULT_MAX_ERROR_LIMIT))

	showValuesCheck := widget.NewCheck("Show failing values in errors", nil)
	showValuesCheck.SetChecked(true)

	flagsContent := container.NewVBox(
		makeFlagRow("Schema variant (--variant):", variantEntry),
		makeFlagRow("Force schema file (--force):", forceSchemaEntry),
		makeFlagRow("Max errors shown (--error-limit):", maxErrorsEntry),
		showValuesCheck,
	)
	flagsPanel := widgets.NewSidePanel("Validate Options", flagsContent, true)

	// ── File picker ───────────────────────────────────────────────
	var filePath string
	picker := widgets.NewFilePicker("BOM file:", state.BOMFile(), w, func(p string) {
		state.SetBOMFile(p)
	})
	// Subscribe so this screen's filePath and picker display stay in sync
	// when another tab selects a file.
	state.OnBOMFileChange(func(p string) {
		filePath = p
		if p != picker.GetPath() {
			fyne.Do(func() { picker.SetPath(p) })
		}
	})

	// ── Shared run logic (button + auto-activate) ─────────────────
	s.run = func() {
		if filePath == "" {
			return
		}

		maxErr := cmd.DEFAULT_MAX_ERROR_LIMIT
		if n, err := fmt.Sscanf(maxErrorsEntry.Text, "%d", &maxErr); n == 0 || err != nil {
			maxErr = cmd.DEFAULT_MAX_ERROR_LIMIT
		}

		fyne.Do(func() {
			results.SetText("Running validation…")
			statusLabel.SetText("")
		})

		go func() {
			res := bridge.RunValidate(bridge.ValidateParams{
				InputFile:     filePath,
				SchemaVariant: variantEntry.Text,
				ForceSchema:   forceSchemaEntry.Text,
				MaxErrors:     maxErr,
				ShowValues:    showValuesCheck.Checked,
			})

			// Format output for the results view
			var sb strings.Builder
			if res.Err != nil {
				if res.Valid {
					// ValidateResult.Err can be non-nil even when valid (informational)
					sb.WriteString(res.Output)
				} else {
					sb.WriteString(res.Output)
					sb.WriteString("\n")
					sb.WriteString("[ERROR] " + res.Err.Error())
				}
			} else {
				if res.Output != "" {
					sb.WriteString(res.Output)
				} else {
					sb.WriteString("BOM document is VALID — no schema errors found.")
				}
			}

			errSummary := ""
			if res.Err != nil && !res.Valid {
				errSummary = firstLine(res.Err.Error())
			}

			// All Fyne UI updates must happen on the main thread.
			text := sb.String()
			valid := res.Valid
			fyne.Do(func() {
				results.SetText(text)
				setStatus(valid, errSummary)
			})
		}()
	}

	// ── Run button ────────────────────────────────────────────────
	runBtn := widget.NewButtonWithIcon("Validate", theme.ConfirmIcon(), func() {
		if filePath == "" {
			results.SetText("[ERROR] No input file selected.")
			return
		}
		s.run()
	})
	runBtn.Importance = widget.HighImportance

	// ── Layout assembly ───────────────────────────────────────────
	// Top bar: file picker + run button
	topBar := container.NewBorder(nil, nil, nil, runBtn, picker.CanvasObject())

	// Middle: status badge
	middleBar := container.NewVBox(
		widget.NewSeparator(),
		statusRow,
		widget.NewSeparator(),
	)

	// Side panel on the left, results on the right
	splitView := container.NewHSplit(
		container.NewVScroll(flagsPanel.CanvasObject()),
		results.CanvasObject(),
	)
	splitView.SetOffset(0.28) // flags panel takes ~28% of horizontal space

	return container.NewBorder(
		container.NewVBox(topBar, middleBar),
		nil, nil, nil,
		splitView,
	)
}

// firstLine returns the first line of a multi-line string.
func firstLine(s string) string {
	if idx := strings.IndexByte(s, '\n'); idx >= 0 {
		return s[:idx]
	}
	return s
}

// makeFlagRow creates a two-row label+widget combo for the flags panel.
func makeFlagRow(label string, w fyne.CanvasObject) fyne.CanvasObject {
	return container.NewVBox(
		widget.NewLabelWithStyle(label, fyne.TextAlignLeading, fyne.TextStyle{Bold: false, Italic: true}),
		w,
	)
}
