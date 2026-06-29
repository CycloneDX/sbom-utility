// SPDX-License-Identifier: Apache-2.0

package screens

import (
	"os"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	guitheme "github.com/CycloneDX/sbom-utility/gui/theme"
)

// ViewScreen displays the raw contents of the loaded BOM file.
// It is the default screen shown after a BOM is loaded.
type ViewScreen struct {
	filePath string
	refresh  func() // populated by Layout; called by Activate
}

// NewViewScreen allocates a ViewScreen.
func NewViewScreen() *ViewScreen { return &ViewScreen{} }

// Activate reloads and displays the BOM file contents.
func (s *ViewScreen) Activate() {
	if s.refresh != nil {
		s.refresh()
	}
}

// Layout constructs and returns the full screen CanvasObject.
func (s *ViewScreen) Layout(_ fyne.Window, state *AppState) fyne.CanvasObject {
	jsonView := widget.NewMultiLineEntry()
	jsonView.Wrapping = fyne.TextWrapOff
	jsonView.TextStyle = fyne.TextStyle{Monospace: true}
	jsonView.SetPlaceHolder("No BOM file loaded — click \"Load BOM\" in the sidebar.")
	// Do NOT call Disable() — a disabled Entry bypasses the ThemeOverride and
	// renders text/background using the global disabled-colour tokens instead of
	// the viewer palette.  The entry is intentionally left enabled so users can
	// select and copy text; it is effectively read-only because no editing is
	// expected in a source-viewer context.

	viewerTheme := guitheme.NewViewerTheme(fyne.CurrentApp().Settings().Theme())

	pathLabel := widget.NewLabelWithStyle(
		"No file loaded.",
		fyne.TextAlignLeading,
		fyne.TextStyle{Italic: true},
	)
	pathLabel.Wrapping = fyne.TextWrapWord

	// themedViewer is declared before loadContent so the closure can call Refresh
	// on it after every text change to ensure the viewer palette sticks.
	themedViewer := container.NewThemeOverride(container.NewScroll(jsonView), viewerTheme)

	loadContent := func(p string) {
		if p == "" {
			fyne.Do(func() {
				pathLabel.SetText("No file loaded.")
				jsonView.SetText("")
				themedViewer.Refresh()
			})
			return
		}
		fyne.Do(func() { pathLabel.SetText("Loaded: " + p) })
		go func() {
			data, err := os.ReadFile(p)
			var text string
			if err != nil {
				text = "[ERROR] could not read file: " + err.Error()
			} else {
				text = string(data)
			}
			// Refresh the ThemeOverride in the same fyne.Do block as SetText so
			// the dark palette is applied immediately after the content changes.
			fyne.Do(func() {
				jsonView.SetText(text)
				themedViewer.Refresh()
			})
		}()
	}

	s.refresh = func() { loadContent(s.filePath) }

	state.OnBOMFileChange(func(p string) {
		s.filePath = p
		loadContent(p)
	})

	top := container.NewVBox(pathLabel, widget.NewSeparator())
	return container.NewBorder(top, nil, nil, nil, themedViewer)
}
