// SPDX-License-Identifier: Apache-2.0

package widgets

import (
	"image/color"
	"path/filepath"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

// StatusBar is a fixed-height bar divided into three sections (25 / 50 / 25 %)
// displayed at the bottom of the application window.
//
//   - Left  (25%): CycloneDX specVersion once a BOM is loaded (empty on init)
//   - Middle(50%): base-name of the loaded BOM file (tooltip shows the full file path on hover)
//   - Right (25%): reserved / future use
//
// The background is RGB(52,120,198) with white foreground text.
type StatusBar struct {
	left     *statusBarLabel
	middle   *statusBarLabel
	right    *statusBarLabel
	outer    fyne.CanvasObject
}

var statusBarBg = color.NRGBA{R: 52, G: 120, B: 198, A: 255}

// NewStatusBar constructs a StatusBar with an empty left section on init.
// The left section is populated with the CycloneDX spec version once a BOM is loaded.
func NewStatusBar() *StatusBar {
	sb := &StatusBar{
		left:   newStatusBarLabel(""),
		middle: newStatusBarLabel(""),
		right:  newStatusBarLabel(""),
	}

	innerGrid := container.New(
		&proportionalHLayout{weights: []float32{1, 2, 1}},
		container.New(layout.NewCustomPaddedLayout(0, 0, 4, 4), sb.left),
		container.New(layout.NewCustomPaddedLayout(0, 0, 4, 4), sb.middle),
		container.New(layout.NewCustomPaddedLayout(0, 0, 4, 4), sb.right),
	)

	// Fixed-height background stripe
	bg := canvas.NewRectangle(statusBarBg)
	bg.SetMinSize(fyne.NewSize(0, 24))

	sb.outer = container.NewStack(bg, innerGrid)
	return sb
}

// CanvasObject returns the embeddable Fyne object to place at the bottom of the
// window via container.NewBorder(…, statusBar.CanvasObject(), …).
func (sb *StatusBar) CanvasObject() fyne.CanvasObject {
	return sb.outer
}

// SetLeft updates the left-section text.
func (sb *StatusBar) SetLeft(text string) {
	sb.left.SetText(text)
}

// SetMiddle updates the middle-section label text and its hover tooltip.
// Pass an empty fullPath to clear the tooltip.
func (sb *StatusBar) SetMiddle(baseName, fullPath string) {
	sb.middle.SetText(baseName)
	sb.middle.SetTooltip(fullPath)
}

// UpdateForBOM refreshes both the left (specVersion) and middle (filename)
// sections from the provided BOM metadata.  Pass empty strings to reset.
func (sb *StatusBar) UpdateForBOM(specVersion, filePath string) {
	if specVersion != "" {
		sb.SetLeft("CycloneDX " + specVersion)
	}
	if filePath != "" {
		sb.SetMiddle(filepath.Base(filePath), filePath)
	} else {
		sb.SetMiddle("", "")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// statusBarLabel — a white-text label that shows a popup tooltip on hover.
// ──────────────────────────────────────────────────────────────────────────────

// statusBarLabel is a custom widget that renders white text and shows a
// popup tooltip when the mouse hovers over it (if a tooltip string is set).
type statusBarLabel struct {
	widget.BaseWidget

	text    string
	tooltip string
	popup   *widget.PopUp
}

var _ fyne.Widget = (*statusBarLabel)(nil)
var _ desktop.Hoverable = (*statusBarLabel)(nil)

func newStatusBarLabel(text string) *statusBarLabel {
	l := &statusBarLabel{text: text}
	l.ExtendBaseWidget(l)
	return l
}

// SetText updates the displayed text.
func (l *statusBarLabel) SetText(text string) {
	l.text = text
	l.Refresh()
}

// SetTooltip sets the text that appears in the hover popup.
func (l *statusBarLabel) SetTooltip(tip string) {
	l.tooltip = tip
}

// CreateRenderer satisfies fyne.Widget; renders the label as white canvas text.
func (l *statusBarLabel) CreateRenderer() fyne.WidgetRenderer {
	txt := canvas.NewText(l.text, color.White)
	txt.TextSize = 12
	return &statusBarLabelRenderer{label: l, text: txt}
}

// MouseIn shows the tooltip popup when the cursor enters the widget area.
func (l *statusBarLabel) MouseIn(ev *desktop.MouseEvent) {
	if l.tooltip == "" {
		return
	}
	c := fyne.CurrentApp().Driver().CanvasForObject(l)
	if c == nil {
		return
	}
	tipLabel := widget.NewLabel(l.tooltip)
	l.popup = widget.NewPopUp(tipLabel, c)
	// Position just above the widget.
	pos := fyne.CurrentApp().Driver().AbsolutePositionForObject(l)
	popSize := l.popup.MinSize()
	l.popup.ShowAtPosition(fyne.NewPos(pos.X, pos.Y-popSize.Height-4))
}

// MouseMoved is required by desktop.Hoverable; no-op.
func (l *statusBarLabel) MouseMoved(_ *desktop.MouseEvent) {}

// MouseOut hides the tooltip popup when the cursor leaves.
func (l *statusBarLabel) MouseOut() {
	if l.popup != nil {
		l.popup.Hide()
		l.popup = nil
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// statusBarLabelRenderer
// ──────────────────────────────────────────────────────────────────────────────

type statusBarLabelRenderer struct {
	label *statusBarLabel
	text  *canvas.Text
}

func (r *statusBarLabelRenderer) Layout(size fyne.Size) {
	r.text.Resize(size)
	r.text.Move(fyne.NewPos(0, 0))
}

func (r *statusBarLabelRenderer) MinSize() fyne.Size {
	return r.text.MinSize()
}

func (r *statusBarLabelRenderer) Refresh() {
	r.text.Text = r.label.text
	r.text.Color = color.White
	r.text.TextSize = 12
	canvas.Refresh(r.text)
}

func (r *statusBarLabelRenderer) Objects() []fyne.CanvasObject {
	return []fyne.CanvasObject{r.text}
}

func (r *statusBarLabelRenderer) Destroy() {}

// ──────────────────────────────────────────────────────────────────────────────
// proportionalHLayout divides available width among N children according to
// integer weight ratios.
// ──────────────────────────────────────────────────────────────────────────────

type proportionalHLayout struct {
	weights []float32
}

func (p *proportionalHLayout) totalWeight() float32 {
	var t float32
	for _, w := range p.weights {
		t += w
	}
	return t
}

func (p *proportionalHLayout) Layout(objects []fyne.CanvasObject, containerSize fyne.Size) {
	total := p.totalWeight()
	x := float32(0)
	for i, obj := range objects {
		weight := float32(0)
		if i < len(p.weights) {
			weight = p.weights[i]
		}
		w := containerSize.Width * weight / total
		obj.Resize(fyne.NewSize(w, containerSize.Height))
		obj.Move(fyne.NewPos(x, 0))
		x += w
	}
}

func (p *proportionalHLayout) MinSize(objects []fyne.CanvasObject) fyne.Size {
	var minW, minH float32
	for _, obj := range objects {
		ms := obj.MinSize()
		minW += ms.Width
		if ms.Height > minH {
			minH = ms.Height
		}
	}
	return fyne.NewSize(minW, minH)
}
