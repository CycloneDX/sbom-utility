// SPDX-License-Identifier: Apache-2.0

package main

import (
	"image/color"
	"os"
	"path/filepath"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/CycloneDX/sbom-utility/cmd"
	"github.com/CycloneDX/sbom-utility/gui/screens"
	guitheme "github.com/CycloneDX/sbom-utility/gui/theme"
	"github.com/CycloneDX/sbom-utility/log"
	"github.com/CycloneDX/sbom-utility/schema"
	"github.com/CycloneDX/sbom-utility/utils"
)

var (
	Project = utils.PROJECT_NAME
	Binary  = "gui"
	Version = "x.y.z"
	Logger  *log.MiniLogger

	DefaultLogLevel = log.ERROR
)

func init() {
	Logger = log.NewLogger(DefaultLogLevel)
	Logger.InitLogLevelAndModeFromFlags()

	cmd.ProjectLogger = Logger
	schema.ProjectLogger = Logger

	utils.GlobalFlags.Project = Project
	utils.GlobalFlags.Binary = Binary
	utils.GlobalFlags.Version = Version

	utils.GlobalFlags.WorkingDir, _ = os.Getwd()
	if execNameWithPath, err := os.Executable(); err == nil {
		utils.GlobalFlags.ExecDir = filepath.Dir(execNameWithPath)
	}

	if err := cmd.SupportedFormatConfig.LoadSchemaConfigFile(
		utils.GlobalFlags.ConfigSchemaFile, "config.json"); err != nil {
		Logger.Warningf("schema config load warning: %v", err)
	}

	cmd.LicensePolicyConfig = new(schema.LicensePolicyConfig)
	if err := cmd.LicensePolicyConfig.LoadHashPolicyConfigurationFile(
		utils.GlobalFlags.ConfigLicensePolicyFile, "license.json"); err != nil {
		Logger.Warningf("license policy load warning: %v", err)
	}
}

func main() {
	a := app.New()
	a.Settings().SetTheme(&guitheme.MacOSTheme{})

	w := a.NewWindow("SBOM Utility — CycloneDX")
	w.Resize(fyne.NewSize(1100, 720))
	w.SetMaster()

	state := screens.NewAppState()

	// ── Build all screen content panes ────────────────────────────
	loadScreen := screens.NewLoadScreen()
	validateScreen := screens.NewValidateScreen()
	licenseScreen := screens.NewLicenseScreen()
	componentScreen := screens.NewComponentScreen()
	resourceScreen := screens.NewResourceScreen()
	vulnScreen := screens.NewVulnerabilityScreen()

	loadContent := loadScreen.ContentLayout(w, state)
	validateContent := validateScreen.Layout(w, state)
	licenseContent := licenseScreen.Layout(w, state)
	componentContent := componentScreen.Layout(w, state)
	resourceContent := resourceScreen.Layout(w, state)
	vulnContent := vulnScreen.Layout(w, state)

	// ── Content stack: only the active pane is shown ──────────────
	// We use a MaxLayout (container.New with layout.NewMaxLayout is container.NewMax/NewStack).
	// Show/hide individual panes to switch between them.
	allPanes := []fyne.CanvasObject{
		loadContent,
		validateContent,
		licenseContent,
		componentContent,
		resourceContent,
		vulnContent,
	}

	showPane := func(idx int) {
		for i, p := range allPanes {
			if i == idx {
				p.Show()
			} else {
				p.Hide()
			}
		}
	}

	// Start with the load pane visible; all others hidden.
	for _, p := range allPanes[1:] {
		p.Hide()
	}

	contentStack := container.NewStack(allPanes...)

	// ── Sidebar nav buttons ───────────────────────────────────────
	// Each button is leading-aligned to match the Fyne tab style.
	// Tool buttons are stored so they can be disabled/enabled.
	makeNavBtn := func(label string, icon fyne.Resource, paneIdx int, runner screens.Runner) *widget.Button {
		btn := widget.NewButtonWithIcon(label, icon, func() {
			showPane(paneIdx)
			if state.BOMFile() != "" && runner != nil {
				runner.Activate()
			}
		})
		btn.Alignment = widget.ButtonAlignLeading
		return btn
	}

	loadBtn := makeNavBtn("Load BOM", theme.FolderOpenIcon(), 0, nil)
	// Override: Load BOM opens the dialog instead of just switching panes.
	loadBtn.OnTapped = func() {
		showPane(0)
		loadScreen.OpenDialog()
	}

	validateBtn := makeNavBtn("Validate", theme.ConfirmIcon(), 1, validateScreen)
	licensesBtn := makeNavBtn("Licenses", theme.InfoIcon(), 2, licenseScreen)
	componentsBtn := makeNavBtn("Components", theme.ListIcon(), 3, componentScreen)
	resourcesBtn := makeNavBtn("Resources", theme.StorageIcon(), 4, resourceScreen)
	vulnBtn := makeNavBtn("Vulnerabilities", theme.WarningIcon(), 5, vulnScreen)

	toolBtns := []*widget.Button{validateBtn, licensesBtn, componentsBtn, resourcesBtn, vulnBtn}

	// Tool buttons start disabled until a BOM is loaded.
	for _, b := range toolBtns {
		b.Disable()
	}

	// Enable tool buttons when a BOM is loaded.
	state.OnBOMFileChange(func(path string) {
		if path == "" {
			return
		}
		fyne.Do(func() {
			for _, b := range toolBtns {
				b.Enable()
			}
		})
	})

	// ── Sidebar layout ────────────────────────────────────────────
	sidebarBg := canvas.NewRectangle(color.NRGBA{R: 0x00, G: 0x00, B: 0x8B, A: 0xFF}) // dark blue
	sidebarNav := container.NewVBox(
		loadBtn,
		widget.NewSeparator(),
		validateBtn,
		licensesBtn,
		componentsBtn,
		resourcesBtn,
		vulnBtn,
	)
	sidebarPadded := container.New(layout.NewCustomPaddedLayout(4, 4, 10, 10), sidebarNav)
	sidebar := container.NewStack(sidebarBg, sidebarPadded)

	w.SetContent(container.NewBorder(nil, nil, sidebar, nil, contentStack))
	w.ShowAndRun()
}
