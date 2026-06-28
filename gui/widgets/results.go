// SPDX-License-Identifier: Apache-2.0

package widgets

import (
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

// ResultsView is a scrollable text area used to display command output.
// It supports two rendering modes:
//   - plain text (default): monospace entry widget inside a bidirectional scroll
//   - markdown: Fyne RichText widget inside a vertical-only scroll
type ResultsView struct {
	entry      *widget.Entry
	richText   *widget.RichText
	plainScroll *container.Scroll
	mdScroll    *container.Scroll
	stack       *fyne.Container // holds both scrolls; only one visible at a time
	markdownOn  bool
}

// NewResultsView creates a read-only, scrollable text area (plain-text mode by default).
func NewResultsView() *ResultsView {
	rv := &ResultsView{}

	entry := widget.NewMultiLineEntry()
	entry.Wrapping = fyne.TextWrapOff
	entry.TextStyle = fyne.TextStyle{Monospace: true}
	entry.SetPlaceHolder("Results will appear here…")
	rv.entry = entry
	rv.plainScroll = container.NewScroll(entry)

	// RichText must live in a VScroll (vertical only) so it receives a finite
	// width from the layout and can correctly reflow wrapped markdown content.
	richText := widget.NewRichTextFromMarkdown("")
	richText.Wrapping = fyne.TextWrapWord
	rv.richText = richText
	rv.mdScroll = container.NewVScroll(richText)

	// Stack both scrolls; swap visibility on mode change.
	rv.stack = container.NewStack(rv.plainScroll, rv.mdScroll)
	rv.mdScroll.Hide()

	return rv
}

// SetMarkdownMode switches between plain-text and markdown rendering.
// The caller is responsible for calling SetText afterwards to populate the view.
func (rv *ResultsView) SetMarkdownMode(md bool) {
	if rv.markdownOn == md {
		return
	}
	rv.markdownOn = md
	if md {
		rv.plainScroll.Hide()
		rv.mdScroll.Show()
	} else {
		rv.mdScroll.Hide()
		rv.plainScroll.Show()
	}
	rv.stack.Refresh()
}

// SetText replaces the content of the results area.
// In markdown mode the text is rendered as Markdown; otherwise it is plain text.
func (rv *ResultsView) SetText(text string) {
	if rv.markdownOn {
		rv.richText.ParseMarkdown(text)
	} else {
		rv.entry.SetText(text)
	}
}

// AppendText adds text to the bottom of the results area (plain-text mode only).
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
	rv.richText.ParseMarkdown("")
}

// CanvasObject returns the embeddable Fyne layout.
func (rv *ResultsView) CanvasObject() fyne.CanvasObject {
	return rv.stack
}
