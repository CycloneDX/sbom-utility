// SPDX-License-Identifier: Apache-2.0

package widgets

import (
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	guitheme "github.com/CycloneDX/sbom-utility/gui/theme"
)

// ResultsView is a scrollable text area used to display command output.
// It supports two rendering modes:
//   - plain text (default): monospace entry widget inside a bidirectional scroll
//   - markdown: VBox of RichText blocks and native widget.Table objects inside a
//     vertical-only scroll. This is required because widget.RichText cannot render
//     GFM pipe tables; we parse them out and hand them to widget.Table instead.
type ResultsView struct {
	entry        *widget.Entry
	plainScroll  *container.Scroll
	mdVBox       *fyne.Container
	mdScroll     *container.Scroll
	stack        *fyne.Container        // holds both scrolls; only one visible at a time
	themed       fyne.CanvasObject      // ThemeOverride wrapping the stack
	markdownOn   bool
}

// NewResultsView creates a read-only, scrollable text area (plain-text mode by default).
// The results area uses the same dark viewer palette as the View screen.
func NewResultsView() *ResultsView {
	rv := &ResultsView{}

	entry := widget.NewMultiLineEntry()
	entry.Wrapping = fyne.TextWrapOff
	entry.TextStyle = fyne.TextStyle{Monospace: true}
	entry.SetPlaceHolder("Results will appear here…")
	rv.entry = entry
	rv.plainScroll = container.NewScroll(entry)

	// The markdown pane is a VBox that will be populated dynamically by SetText.
	// It lives inside a VScroll so it gets a finite width for text reflow.
	rv.mdVBox = container.NewVBox()
	rv.mdScroll = container.NewVScroll(rv.mdVBox)

	// Stack both scrolls; swap visibility on mode change.
	rv.stack = container.NewStack(rv.plainScroll, rv.mdScroll)
	rv.mdScroll.Hide()

	// Wrap the stack in the same dark viewer theme used by the View screen.
	viewerTheme := guitheme.NewViewerTheme(fyne.CurrentApp().Settings().Theme())
	rv.themed = container.NewThemeOverride(rv.stack, viewerTheme)

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
// In markdown mode the text is parsed into text blocks and pipe tables,
// each rendered with the appropriate Fyne widget, then stacked in a VBox.
func (rv *ResultsView) SetText(text string) {
	if rv.markdownOn {
		rv.mdVBox.Objects = buildMarkdownObjects(text)
		rv.mdVBox.Refresh()
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
	rv.mdVBox.Objects = nil
	rv.mdVBox.Refresh()
}

// CanvasObject returns the embeddable Fyne layout.
func (rv *ResultsView) CanvasObject() fyne.CanvasObject {
	return rv.themed
}

// ── Markdown table parsing ────────────────────────────────────────────────────

// mdSegment represents a contiguous block that is either a markdown text block
// or a parsed pipe table.
type mdSegment struct {
	isTable bool
	text    string     // valid when isTable == false
	rows    [][]string // valid when isTable == true; row 0 is the header
}

// parseMarkdownSegments splits a markdown string into alternating text/table
// segments. A block is only treated as a GFM pipe table when it contains a
// proper separator row (|---|---|); otherwise the lines are kept as plain text
// so that error messages or other pipe-prefixed text render via RichText.
func parseMarkdownSegments(md string) []mdSegment {
	lines := strings.Split(md, "\n")
	var segments []mdSegment
	var textLines []string

	flushText := func() {
		if len(textLines) == 0 {
			return
		}
		// Trim trailing blank lines so we don't add excessive whitespace above tables.
		for len(textLines) > 0 && strings.TrimSpace(textLines[len(textLines)-1]) == "" {
			textLines = textLines[:len(textLines)-1]
		}
		if len(textLines) > 0 {
			segments = append(segments, mdSegment{text: strings.Join(textLines, "\n")})
		}
		textLines = nil
	}

	i := 0
	for i < len(lines) {
		line := lines[i]
		if isTableLine(line) {
			// Speculatively collect all consecutive pipe-table lines.
			var tableLines []string
			j := i
			for j < len(lines) && (isTableLine(lines[j]) || strings.TrimSpace(lines[j]) == "") {
				if isTableLine(lines[j]) {
					tableLines = append(tableLines, lines[j])
				}
				j++
			}
			// Only treat this as a real table if at least one separator row is
			// present. Without a separator it is ambiguous (e.g. an error message
			// that happens to start with '|'), so fall through to plain text.
			if hasTableSeparator(tableLines) {
				flushText()
				i = j
				seg := mdSegment{isTable: true, rows: parseTableLines(tableLines)}
				if len(seg.rows) > 0 {
					segments = append(segments, seg)
				}
			} else {
				// Not a real table — accumulate as text lines.
				textLines = append(textLines, line)
				i++
			}
		} else {
			textLines = append(textLines, line)
			i++
		}
	}
	flushText()
	return segments
}

// hasTableSeparator returns true when at least one line in the block is a GFM
// separator row (cells containing only dashes, colons, and spaces).
func hasTableSeparator(lines []string) bool {
	for _, line := range lines {
		if isSeparatorRow(splitTableRow(line)) {
			return true
		}
	}
	return false
}

// isTableLine returns true if the line looks like a GFM pipe-table row.
func isTableLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	return len(trimmed) > 0 && trimmed[0] == '|'
}

// isSeparatorRow returns true for rows like |---|:---:|---.
func isSeparatorRow(cells []string) bool {
	for _, c := range cells {
		t := strings.Trim(c, " :-")
		if t != "" {
			return false
		}
	}
	return true
}

// parseTableLines converts raw pipe-table lines into a 2-D string slice.
// Row 0 is the header; the separator row is stripped.
func parseTableLines(lines []string) [][]string {
	var rows [][]string
	for _, line := range lines {
		cells := splitTableRow(line)
		if isSeparatorRow(cells) {
			continue
		}
		rows = append(rows, cells)
	}
	return rows
}

// splitTableRow splits a GFM table row on '|', trimming whitespace from each cell.
func splitTableRow(line string) []string {
	trimmed := strings.TrimSpace(line)
	trimmed = strings.Trim(trimmed, "|")
	parts := strings.Split(trimmed, "|")
	cells := make([]string, len(parts))
	for i, p := range parts {
		cells[i] = strings.TrimSpace(p)
	}
	return cells
}

// buildMarkdownObjects converts the parsed segments into a slice of Fyne
// CanvasObjects ready to be placed inside a VBox.
func buildMarkdownObjects(md string) []fyne.CanvasObject {
	segments := parseMarkdownSegments(md)
	if len(segments) == 0 {
		return nil
	}
	objects := make([]fyne.CanvasObject, 0, len(segments))
	for _, seg := range segments {
		if seg.isTable {
			objects = append(objects, buildTableWidget(seg.rows))
		} else {
			rt := widget.NewRichTextFromMarkdown(seg.text)
			rt.Wrapping = fyne.TextWrapWord
			objects = append(objects, rt)
		}
	}
	return objects
}

// buildTableWidget builds a native widget.Table from the row data.
// Row 0 is treated as the header and rendered in bold.
func buildTableWidget(rows [][]string) fyne.CanvasObject {
	if len(rows) == 0 {
		return widget.NewLabel("")
	}
	cols := len(rows[0])

	tbl := widget.NewTable(
		func() (int, int) { return len(rows), cols },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(id widget.TableCellID, obj fyne.CanvasObject) {
			lbl := obj.(*widget.Label)
			if id.Row < len(rows) && id.Col < len(rows[id.Row]) {
				lbl.SetText(rows[id.Row][id.Col])
			} else {
				lbl.SetText("")
			}
			lbl.TextStyle = fyne.TextStyle{Bold: id.Row == 0}
			lbl.Refresh()
		},
	)

	// Estimate column widths based on the widest cell content in each column.
	for c := 0; c < cols; c++ {
		maxLen := 0
		for _, row := range rows {
			if c < len(row) && len(row[c]) > maxLen {
				maxLen = len(row[c])
			}
		}
		// ~7 px per character, minimum 60 px.
		width := float32(maxLen)*7 + 16
		if width < 60 {
			width = 60
		}
		tbl.SetColumnWidth(c, width)
	}

	// Constrain the table to a fixed height while letting it expand to full
	// available width. GridWrap with width=0 collapses the widget, so we use
	// a custom single-child layout that fills width and pins height.
	rowHeight := float32(34)
	tableH := rowHeight * float32(len(rows))
	if tableH < rowHeight {
		tableH = rowHeight
	}
	return container.New(newFixedHeightLayout(tableH), tbl)
}

// fixedHeightLayout is a single-child layout that gives the child the full
// container width and a caller-supplied fixed height.
type fixedHeightLayout struct{ height float32 }

func newFixedHeightLayout(h float32) fyne.Layout { return fixedHeightLayout{h} }

func (f fixedHeightLayout) MinSize(_ []fyne.CanvasObject) fyne.Size {
	return fyne.NewSize(0, f.height)
}

func (f fixedHeightLayout) Layout(objects []fyne.CanvasObject, containerSize fyne.Size) {
	for _, o := range objects {
		o.Resize(fyne.NewSize(containerSize.Width, f.height))
		o.Move(fyne.NewPos(0, 0))
	}
}

