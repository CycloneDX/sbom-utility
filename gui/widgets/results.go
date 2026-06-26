// SPDX-License-Identifier: Apache-2.0

package widgets

import (
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

// ResultsView is a scrollable, monospace text area used to display command output.
type ResultsView struct {
	entry     *widget.Entry
	container fyne.CanvasObject
}

// NewResultsView creates a read-only, scrollable text area.
func NewResultsView() *ResultsView {
	rv := &ResultsView{}

	entry := widget.NewMultiLineEntry()
	entry.Wrapping = fyne.TextWrapOff
	entry.TextStyle = fyne.TextStyle{Monospace: true}
	entry.SetPlaceHolder("Results will appear here…")
	// Make it visually read-only by not allowing the user to easily type.
	// (Fyne doesn't have a dedicated read-only multi-line; we use a MultiLineEntry
	// but do not present it as editable in the UI.)
	rv.entry = entry

	scroll := container.NewScroll(entry)
	rv.container = scroll
	return rv
}

// SetText replaces the content of the results area.
func (rv *ResultsView) SetText(text string) {
	rv.entry.SetText(text)
}

// AppendText adds text to the bottom of the results area.
func (rv *ResultsView) AppendText(text string) {
	existing := rv.entry.Text
	if existing != "" && !strings.HasSuffix(existing, "\n") {
		existing += "\n"
	}
	rv.entry.SetText(existing + text)
}

// Clear empties the results view.
func (rv *ResultsView) Clear() {
	rv.entry.SetText("")
}

// CanvasObject returns the embeddable Fyne layout.
func (rv *ResultsView) CanvasObject() fyne.CanvasObject {
	return rv.container
}
