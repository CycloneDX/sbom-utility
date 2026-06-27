// SPDX-License-Identifier: Apache-2.0

// Package theme provides a macOS-inspired Fyne theme for the SBOM Utility GUI.
// It mirrors macOS Ventura/Sonoma light-mode aesthetics:
//   - System background  #F5F5F5  (window chrome grey)
//   - Content background #FFFFFF  (white panels)
//   - Sidebar/header     #EBEBEB  (sidebar grey)
//   - Accent blue        #007AFF  (macOS system blue)
//   - Primary text       #1D1D1F
//   - Secondary text     #6E6E73
//   - Border/separator   #D2D2D7
//   - Input background   #FFFFFF with a subtle border
//   - Font sizes matching macOS HIG (body 13 pt, caption 11 pt, heading 17 pt)
package theme

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// MacOSTheme is a Fyne theme that approximates macOS Ventura/Sonoma light mode.
type MacOSTheme struct{}

// Ensure MacOSTheme satisfies fyne.Theme at compile time.
var _ fyne.Theme = (*MacOSTheme)(nil)

// ── colors ──────────────────────────────────────────────────────────────────

// macOS system palette (light mode).
var (
	colorBackground    = color.NRGBA{R: 0xF5, G: 0xF5, B: 0xF5, A: 0xFF} // window chrome
	colorContent       = color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF} // white panels
	colorSidebar       = color.NRGBA{R: 0xEB, G: 0xEB, B: 0xEB, A: 0xFF} // sidebar / header rows
	colorAccentBlue    = color.NRGBA{R: 0x00, G: 0x7A, B: 0xFF, A: 0xFF} // macOS system blue
	colorAccentBlueDim = color.NRGBA{R: 0x00, G: 0x7A, B: 0xFF, A: 0x33} // selection / focus ring
	colorForeground    = color.NRGBA{R: 0x1D, G: 0x1D, B: 0x1F, A: 0xFF} // primary text
	colorSecondary     = color.NRGBA{R: 0x6E, G: 0x6E, B: 0x73, A: 0xFF} // secondary text / placeholder
	colorBorder        = color.NRGBA{R: 0xD2, G: 0xD2, B: 0xD7, A: 0xFF} // separator / input border
	colorError         = color.NRGBA{R: 0xFF, G: 0x3B, B: 0x30, A: 0xFF} // macOS red
	colorWarning       = color.NRGBA{R: 0xFF, G: 0x9F, B: 0x0A, A: 0xFF} // macOS amber
	colorSuccess       = color.NRGBA{R: 0x30, G: 0xD1, B: 0x58, A: 0xFF} // macOS green
	colorHover         = color.NRGBA{R: 0x00, G: 0x7A, B: 0xFF, A: 0x14} // very light blue tint
	colorPressed       = color.NRGBA{R: 0x00, G: 0x7A, B: 0xFF, A: 0x22} // slightly stronger on press
	colorScrollBar     = color.NRGBA{R: 0xC0, G: 0xC0, B: 0xC5, A: 0xFF}
	colorScrollBarBg   = color.NRGBA{R: 0xF0, G: 0xF0, B: 0xF0, A: 0xFF}
	colorShadow        = color.NRGBA{R: 0x00, G: 0x00, B: 0x00, A: 0x26} // 15 % black shadow
	colorOverlay       = color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF} // dialogs / popovers
	colorDisabledBtn   = color.NRGBA{R: 0xE0, G: 0xE0, B: 0xE5, A: 0xFF}
	colorDisabledText  = color.NRGBA{R: 0xC0, G: 0xC0, B: 0xC5, A: 0xFF}
	colorHyperlinkBlue = color.NRGBA{R: 0x00, G: 0x6B, B: 0xD6, A: 0xFF}
)

// Color implements fyne.Theme.
func (m *MacOSTheme) Color(name fyne.ThemeColorName, _ fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground:
		return colorBackground
	case theme.ColorNameButton:
		return colorContent
	case theme.ColorNameDisabledButton:
		return colorDisabledBtn
	case theme.ColorNameDisabled:
		return colorDisabledText
	case theme.ColorNameError:
		return colorError
	case theme.ColorNameFocus:
		return colorAccentBlue
	case theme.ColorNameForeground:
		return colorForeground
	case theme.ColorNameForegroundOnError:
		return colorContent
	case theme.ColorNameForegroundOnPrimary:
		return colorContent
	case theme.ColorNameForegroundOnSuccess:
		return colorContent
	case theme.ColorNameForegroundOnWarning:
		return colorContent
	case theme.ColorNameHeaderBackground:
		return colorSidebar
	case theme.ColorNameHover:
		return colorHover
	case theme.ColorNameHyperlink:
		return colorHyperlinkBlue
	case theme.ColorNameInputBackground:
		return colorContent
	case theme.ColorNameInputBorder:
		return colorBorder
	case theme.ColorNameMenuBackground:
		return colorContent
	case theme.ColorNameOverlayBackground:
		return colorOverlay
	case theme.ColorNamePlaceHolder:
		return colorSecondary
	case theme.ColorNamePressed:
		return colorPressed
	case theme.ColorNamePrimary:
		return colorAccentBlue
	case theme.ColorNameScrollBar:
		return colorScrollBar
	case theme.ColorNameScrollBarBackground:
		return colorScrollBarBg
	case theme.ColorNameSelection:
		return colorAccentBlueDim
	case theme.ColorNameSeparator:
		return colorBorder
	case theme.ColorNameShadow:
		return colorShadow
	case theme.ColorNameSuccess:
		return colorSuccess
	case theme.ColorNameWarning:
		return colorWarning
	default:
		// Fall back to Fyne's built-in light theme for anything not listed above.
		return theme.LightTheme().Color(name, theme.VariantLight)
	}
}

// ── fonts ─────────────────────────────────────────────────────────────────────

// Font implements fyne.Theme.
// We use Fyne's bundled fonts because shipping the full San Francisco font is
// not possible without a license.  The bundled fonts are clean sans-serif faces
// that are visually close to SF Pro at the sizes we configure below.
func (m *MacOSTheme) Font(style fyne.TextStyle) fyne.Resource {
	switch {
	case style.Monospace:
		return theme.DefaultTextMonospaceFont()
	case style.Bold && style.Italic:
		return theme.DefaultTextBoldItalicFont()
	case style.Bold:
		return theme.DefaultTextBoldFont()
	case style.Italic:
		return theme.DefaultTextItalicFont()
	default:
		return theme.DefaultTextFont()
	}
}

// ── icons ─────────────────────────────────────────────────────────────────────

// Icon implements fyne.Theme.  We keep Fyne's built-in icons.
func (m *MacOSTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

// ── sizes ─────────────────────────────────────────────────────────────────────

// Size implements fyne.Theme using macOS HIG-inspired metrics.
//
// macOS HIG reference sizes (1 pt ≈ 1 dp on a non-Retina display):
//
//	Body text      13 pt
//	Caption        11 pt
//	Heading        17 pt
//	Sub-heading    15 pt
//	Control height ~22 pt  → padding 4 pt top/bottom
//	Input border    1 pt
//	Corner radius   5 pt   (text fields), 6 pt (controls)
func (m *MacOSTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNameText:
		return 13
	case theme.SizeNameCaptionText:
		return 11
	case theme.SizeNameHeadingText:
		return 17
	case theme.SizeNameSubHeadingText:
		return 15
	case theme.SizeNamePadding:
		return 6
	case theme.SizeNameInnerPadding:
		return 4
	case theme.SizeNameLineSpacing:
		return 4
	case theme.SizeNameInlineIcon:
		return 20
	case theme.SizeNameScrollBar:
		return 8
	case theme.SizeNameScrollBarSmall:
		return 3
	case theme.SizeNameScrollBarRadius:
		return 4
	case theme.SizeNameSeparatorThickness:
		return 1
	case theme.SizeNameInputBorder:
		return 1
	case theme.SizeNameInputRadius:
		return 5
	case theme.SizeNameSelectionRadius:
		return 3
	default:
		return theme.DefaultTheme().Size(name)
	}
}
