// SPDX-License-Identifier: Apache-2.0

package theme

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// ViewerTheme is a local theme override for the BOM source-viewer entry widget.
// It provides a dark-editor look:
//
//	Background / input bg  #1E1E1E  (VS Code-style dark charcoal)
//	Foreground / text       #CECECE  (light grey)
//	Placeholder             #7A7A7A  (dimmer grey)
//
// Font order preference: Consolas → Courier New → system monospace fallback.
// Fyne resolves monospace fonts from the OS; we keep the existing monospace
// resource (DefaultTextMonospaceFont) but set TextStyle.Monospace = true on the
// entry so the host system's preferred monospace font is selected. Consolas and
// Courier are listed in the FyneApp.toml font settings instead of here because
// Fyne's font-loading pipeline requires TTF resources, not font family names.
type ViewerTheme struct {
	// base delegates all unoverridden calls back to the application theme.
	base fyne.Theme
}

// NewViewerTheme creates a ViewerTheme that delegates non-overridden values to
// the supplied base theme (typically the application's active theme).
func NewViewerTheme(base fyne.Theme) *ViewerTheme {
	if base == nil {
		base = theme.DefaultTheme()
	}
	return &ViewerTheme{base: base}
}

// Colour constants for the viewer.
var (
	ViewerBG          = color.NRGBA{R: 0x1E, G: 0x1E, B: 0x1E, A: 0xFF} // #1E1E1E
	ViewerFG          = color.NRGBA{R: 0xCE, G: 0xCE, B: 0xCE, A: 0xFF} // #CECECE
	ViewerPlaceholder = color.NRGBA{R: 0x7A, G: 0x7A, B: 0x7A, A: 0xFF} // #7A7A7A
	ViewerDisabled    = color.NRGBA{R: 0x88, G: 0x88, B: 0x88, A: 0xFF} // slightly lighter placeholder
	ViewerSelection   = color.NRGBA{R: 0x26, G: 0x4F, B: 0x78, A: 0xFF} // muted blue selection
	ViewerCursor      = color.NRGBA{R: 0xCE, G: 0xCE, B: 0xCE, A: 0xFF} // cursor matches FG
	ViewerBorder      = color.NRGBA{R: 0x3C, G: 0x3C, B: 0x3C, A: 0xFF} // subtle border
)

// Color implements fyne.Theme.
func (v *ViewerTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground:
		return ViewerBG
	case theme.ColorNameInputBackground:
		return ViewerBG
	case theme.ColorNameForeground:
		return ViewerFG
	case theme.ColorNamePlaceHolder:
		return ViewerPlaceholder
	case theme.ColorNameDisabled:
		return ViewerDisabled
	case theme.ColorNameSelection:
		return ViewerSelection
	case theme.ColorNameFocus:
		return ViewerCursor
	case theme.ColorNameInputBorder:
		return ViewerBorder
	case theme.ColorNameScrollBar:
		return color.NRGBA{R: 0x60, G: 0x60, B: 0x60, A: 0xFF}
	case theme.ColorNameScrollBarBackground:
		return color.NRGBA{R: 0x2A, G: 0x2A, B: 0x2A, A: 0xFF}
	default:
		return v.base.Color(name, variant)
	}
}

// Font implements fyne.Theme — delegate to base; callers set TextStyle.Monospace = true.
func (v *ViewerTheme) Font(style fyne.TextStyle) fyne.Resource {
	return v.base.Font(style)
}

// Icon implements fyne.Theme — delegate to base.
func (v *ViewerTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return v.base.Icon(name)
}

// Size implements fyne.Theme — delegate to base so font size stays consistent.
func (v *ViewerTheme) Size(name fyne.ThemeSizeName) float32 {
	return v.base.Size(name)
}
