// SPDX-License-Identifier: Apache-2.0

package widgets

import (
	"path/filepath"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// FilePicker is a label + entry + browse-button row that lets the user
// choose a local file path.  OnChanged is called whenever the path changes.
type FilePicker struct {
	entry     *widget.Entry
	container fyne.CanvasObject
}

// NewFilePicker constructs a FilePicker.
//   - label    : short label shown to the left of the entry
//   - initial  : pre-filled path (empty is fine)
//   - window   : the parent window, required for the dialog
//   - onChange : callback with the new path whenever it changes
func NewFilePicker(label string, initial string, window fyne.Window, onChange func(string)) *FilePicker {
	fp := &FilePicker{}

	entry := widget.NewEntry()
	entry.SetPlaceHolder("Select a BOM JSON file…")
	entry.SetText(initial)
	entry.OnChanged = onChange
	fp.entry = entry

	browseBtn := widget.NewButtonWithIcon("Load", theme.FolderOpenIcon(), func() {
		d := dialog.NewFileOpen(func(uc fyne.URIReadCloser, err error) {
			if err != nil || uc == nil {
				return
			}
			path := uc.URI().Path()
			entry.SetText(path)
			if onChange != nil {
				onChange(path)
			}
		}, window)
		d.SetFilter(storage.NewExtensionFileFilter([]string{".json", ".xml"}))
		// Start the dialog in the directory of the current entry value, if set.
		if entry.Text != "" {
			dir := filepath.Dir(entry.Text)
			if luri, err := storage.ListerForURI(storage.NewFileURI(dir)); err == nil {
				d.SetLocation(luri)
			}
		}
		d.SetView(dialog.ListView)
		// Open at a larger size so more files/folders are visible at once.
		// Resize must be called before Show so the dialog renders at the
		// correct dimensions; Fyne file dialogs are resizable by the user.
		d.Resize(fyne.NewSize(800, 600))
		d.Show()
	})

	fp.container = container.NewBorder(
		nil, nil,
		widget.NewLabel(label), browseBtn,
		entry,
	)
	return fp
}

// GetPath returns the current file path value.
func (fp *FilePicker) GetPath() string {
	return fp.entry.Text
}

// SetPath programmatically sets the entry value (does NOT trigger OnChanged).
func (fp *FilePicker) SetPath(path string) {
	fp.entry.SetText(path)
}

// CanvasObject returns the Fyne layout object to embed in a screen.
func (fp *FilePicker) CanvasObject() fyne.CanvasObject {
	return fp.container
}
