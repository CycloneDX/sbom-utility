// SPDX-License-Identifier: Apache-2.0

package screens

import (
	"os"
	"path/filepath"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"

	"github.com/CycloneDX/sbom-utility/gui/bridge"
	guitheme "github.com/CycloneDX/sbom-utility/gui/theme"
)

// LoadScreen owns the file-browse dialog and the JSON viewer shown in the
// main content area.  It does NOT occupy a tab slot; its OpenDialog method
// is called directly from the sidebar load button in main.go.
type LoadScreen struct {
	window fyne.Window
	state  *AppState
}

// NewLoadScreen allocates a LoadScreen.
func NewLoadScreen() *LoadScreen { return &LoadScreen{} }

// OpenDialog opens the Fyne file-open dialog.
func (s *LoadScreen) OpenDialog() {
	if s.window == nil {
		return
	}
	currentPath := s.state.BOMFile()
	d := dialog.NewFileOpen(func(uc fyne.URIReadCloser, err error) {
		if err != nil || uc == nil {
			return
		}
		path := uc.URI().Path()
		s.state.SetBOMFile(path)
		// Parse BOM metadata in the background so the status bar updates.
		go func() {
			info := bridge.LoadBOMInfo(path)
			s.state.SetBOMInfo(BOMInfo{
				Format:      info.Format,
				SpecVersion: info.SpecVersion,
				FilePath:    info.FilePath,
			})
		}()
	}, s.window)
	d.SetFilter(storage.NewExtensionFileFilter([]string{".json", ".xml"}))
	if currentPath != "" {
		dir := filepath.Dir(currentPath)
		if luri, err := storage.ListerForURI(storage.NewFileURI(dir)); err == nil {
			d.SetLocation(luri)
		}
	}
	d.SetView(dialog.ListView)
	d.Resize(fyne.NewSize(800, 600))
	d.Show()
}

// ContentLayout builds the main-area widget tree: a status label at the top
// and a scrollable JSON viewer below.  It is embedded in the window content
// by main.go, not inside a TabItem.
func (s *LoadScreen) ContentLayout(w fyne.Window, state *AppState) fyne.CanvasObject {
	s.window = w
	s.state = state

	jsonView := widget.NewMultiLineEntry()
	jsonView.Wrapping = fyne.TextWrapOff
	jsonView.TextStyle = fyne.TextStyle{Monospace: true}
	jsonView.SetPlaceHolder("No BOM file loaded — click \"Load BOM\" in the sidebar.")
	// Do NOT call Disable() — see view.go for the full explanation.

	viewerTheme := guitheme.NewViewerTheme(fyne.CurrentApp().Settings().Theme())

	pathLabel := widget.NewLabelWithStyle(
		"No file loaded.",
		fyne.TextAlignLeading,
		fyne.TextStyle{Italic: true},
	)
	pathLabel.Wrapping = fyne.TextWrapWord

	// themedViewer is declared before the state callback so the closure can
	// call Refresh on it in the same fyne.Do block as SetText.
	themedViewer := container.NewThemeOverride(container.NewScroll(jsonView), viewerTheme)

	state.OnBOMFileChange(func(p string) {
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
			fyne.Do(func() {
				jsonView.SetText(text)
				themedViewer.Refresh()
			})
		}()
	})

	top := container.NewVBox(pathLabel, widget.NewSeparator())
	return container.NewBorder(top, nil, nil, nil, themedViewer)
}
