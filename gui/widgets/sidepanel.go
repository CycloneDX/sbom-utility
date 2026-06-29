// SPDX-License-Identifier: Apache-2.0

package widgets

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// SidePanel is a collapsible panel that wraps a content object under a toggle button.
// When collapsed, only the toggle bar is visible; when expanded, the full content shows.
type SidePanel struct {
	title     string
	content   fyne.CanvasObject
	expanded  bool
	toggle    *widget.Button
	inner     *fyne.Container
	container fyne.CanvasObject
}

// NewSidePanel creates a collapsible side panel.
//   - title    : label shown on the collapse/expand toggle button
//   - content  : the widget tree inside the panel
//   - expanded : initial state
func NewSidePanel(title string, content fyne.CanvasObject, expanded bool) *SidePanel {
	sp := &SidePanel{
		title:    title,
		content:  content,
		expanded: expanded,
	}

	sp.inner = container.NewVBox(content)
	if !expanded {
		sp.inner.Hide()
	}

	sp.toggle = widget.NewButtonWithIcon(sp.labelText(), theme.MenuDropDownIcon(), sp.toggleState)
	sp.toggle.Alignment = widget.ButtonAlignLeading

	sp.container = container.NewVBox(
		sp.toggle,
		sp.inner,
	)
	return sp
}

func (sp *SidePanel) labelText() string {
	if sp.expanded {
		return "▼  " + sp.title
	}
	return "▶  " + sp.title
}

func (sp *SidePanel) toggleState() {
	sp.expanded = !sp.expanded
	sp.toggle.SetText(sp.labelText())
	if sp.expanded {
		sp.inner.Show()
	} else {
		sp.inner.Hide()
	}
	sp.inner.Refresh()
}

// CanvasObject returns the embeddable Fyne layout.
func (sp *SidePanel) CanvasObject() fyne.CanvasObject {
	return sp.container
}
