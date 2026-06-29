// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/CycloneDX/sbom-utility/cmd"
	"github.com/CycloneDX/sbom-utility/gui/screens"
	guitheme "github.com/CycloneDX/sbom-utility/gui/theme"
	"github.com/CycloneDX/sbom-utility/gui/widgets"
	"github.com/CycloneDX/sbom-utility/log"
	"github.com/CycloneDX/sbom-utility/schema"
	"github.com/CycloneDX/sbom-utility/utils"
)

const AppName = "SBOM Utility GUI"

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

	w := a.NewWindow("CycloneDX - SBOM Utility v" + Version)
	w.Resize(fyne.NewSize(1100, 720))
	w.SetMaster()

	// ── App menu with custom About dialog ─────────────────────────
	// On macOS, Fyne intercepts menu items labelled "About" and moves
	// them into the system app menu, wiring the callback below.
	aboutItem := fyne.NewMenuItem("About", func() {
		msg := fmt.Sprintf(
			"%s  v%s\n\n"+
				"© 2026 CycloneDX Contributors\n\n"+
				"https://github.com/CycloneDX/sbom-utility",
			AppName, Version,
		)
		dialog.ShowInformation("About "+AppName, msg, w)
	})
	w.SetMainMenu(fyne.NewMainMenu(
		fyne.NewMenu(AppName, aboutItem),
	))

	state := screens.NewAppState()

	// ── Build all screen content panes ────────────────────────────
	loadScreen := screens.NewLoadScreen()
	viewScreen := screens.NewViewScreen()
	validateScreen := screens.NewValidateScreen()
	licenseScreen := screens.NewLicenseScreen()
	componentScreen := screens.NewComponentScreen()
	resourceScreen := screens.NewResourceScreen()
	vulnScreen := screens.NewVulnerabilityScreen()

	loadContent := loadScreen.ContentLayout(w, state)
	viewContent := viewScreen.Layout(w, state)
	validateContent := validateScreen.Layout(w, state)
	licenseContent := licenseScreen.Layout(w, state)
	componentContent := componentScreen.Layout(w, state)
	resourceContent := resourceScreen.Layout(w, state)
	vulnContent := vulnScreen.Layout(w, state)

	// ── Content stack: only the active pane is shown ──────────────
	// We use a MaxLayout (container.New with layout.NewMaxLayout is container.NewMax/NewStack).
	// Show/hide individual panes to switch between them.
	//
	// Pane indices:
	//   0 = Load BOM (file picker, not in toolBtns)
	//   1 = View     (default after a BOM is loaded)
	//   2 = Validate
	//   3 = Licenses
	//   4 = Components
	//   5 = Resources
	//   6 = Vulnerabilities
	allPanes := []fyne.CanvasObject{
		loadContent,
		viewContent,
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

	viewBtn := makeNavBtn("View", theme.DocumentIcon(), 1, viewScreen)
	validateBtn := makeNavBtn("Validate", theme.ConfirmIcon(), 2, validateScreen)
	licensesBtn := makeNavBtn("Licenses", theme.InfoIcon(), 3, licenseScreen)
	componentsBtn := makeNavBtn("Components", theme.ListIcon(), 4, componentScreen)
	resourcesBtn := makeNavBtn("Resources", theme.StorageIcon(), 5, resourceScreen)
	vulnBtn := makeNavBtn("Vulnerabilities", theme.WarningIcon(), 6, vulnScreen)

	toolBtns := []*widget.Button{viewBtn, validateBtn, licensesBtn, componentsBtn, resourcesBtn, vulnBtn}

	// Tool buttons start disabled until a BOM is loaded.
	for _, b := range toolBtns {
		b.Disable()
	}

	// Enable tool buttons and switch to the View pane when a BOM is loaded.
	state.OnBOMFileChange(func(path string) {
		if path == "" {
			return
		}
		fyne.Do(func() {
			for _, b := range toolBtns {
				b.Enable()
			}
			// Default to the View pane whenever a new BOM is loaded.
			showPane(1)
		})
	})

	// Load the image
	img := canvas.NewImageFromFile("gui/images/blue-charcoal.png")

	// Stretch to fit the canvas
	img.FillMode = canvas.ImageFillStretch

	// ── Sidebar layout ────────────────────────────────────────────
	sidebarNav := container.NewVBox(
		loadBtn,
		widget.NewSeparator(),
		viewBtn,
		widget.NewSeparator(),
		validateBtn,
		licensesBtn,
		componentsBtn,
		resourcesBtn,
		vulnBtn,
	)
	sidebarPadded := container.New(layout.NewCustomPaddedLayout(4, 4, 10, 10), sidebarNav)
	//sidebarBg := canvas.NewRectangle(color.NRGBA{R: 0x00, G: 0x00, B: 0x8B, A: 0xFF}) // dark blue
	sidebar := container.NewStack(img, sidebarPadded)
	// ── Status bar ────────────────────────────────────────────────
	statusBar := widgets.NewStatusBar()

	state.OnBOMInfoChange(func(info screens.BOMInfo) {
		fyne.Do(func() {
			statusBar.UpdateForBOM(info.Format, info.SpecVersion, info.FilePath)
		})
	})

	appContainer := container.NewBorder(nil, statusBar.CanvasObject(), sidebar, nil, contentStack)
	w.SetContent(appContainer)
	w.ShowAndRun()
}
