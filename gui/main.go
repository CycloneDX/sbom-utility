// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"

	"github.com/CycloneDX/sbom-utility/cmd"
	guitheme "github.com/CycloneDX/sbom-utility/gui/theme"
	"github.com/CycloneDX/sbom-utility/gui/screens"
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

	// Wire up shared loggers (same pattern as main.go)
	cmd.ProjectLogger = Logger
	schema.ProjectLogger = Logger

	utils.GlobalFlags.Project = Project
	utils.GlobalFlags.Binary = Binary
	utils.GlobalFlags.Version = Version

	utils.GlobalFlags.WorkingDir, _ = os.Getwd()
	if execNameWithPath, err := os.Executable(); err == nil {
		utils.GlobalFlags.ExecDir = filepath.Dir(execNameWithPath)
	}

	// Bootstrap the cmd package's shared state (schema config + license policy).
	// initConfigurations() is unexported in cmd, so we replicate its two calls here.
	if err := cmd.SupportedFormatConfig.LoadSchemaConfigFile(
		utils.GlobalFlags.ConfigSchemaFile, "config.json"); err != nil {
		// Non-fatal for the GUI; commands will surface errors per-run.
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

	// Shared state: a single BOM file path that persists across all tabs.
	state := screens.NewAppState()

	// Build screens as named variables so we can call Activate() on tab-switch.
	validateScreen := screens.NewValidateScreen()
	licenseScreen := screens.NewLicenseScreen()
	componentScreen := screens.NewComponentScreen()
	resourceScreen := screens.NewResourceScreen()
	vulnScreen := screens.NewVulnerabilityScreen()

	// Map tab index → Runner so selecting a tab auto-runs its command.
	tabRunners := map[int]screens.Runner{
		0: validateScreen,
		1: licenseScreen,
		2: componentScreen,
		3: resourceScreen,
		4: vulnScreen,
	}

	tabs := container.NewAppTabs(
		container.NewTabItemWithIcon("Validate", theme.ConfirmIcon(), validateScreen.Layout(w, state)),
		container.NewTabItemWithIcon("Licenses", theme.InfoIcon(), licenseScreen.Layout(w, state)),
		container.NewTabItemWithIcon("Components", theme.ListIcon(), componentScreen.Layout(w, state)),
		container.NewTabItemWithIcon("Resources", theme.StorageIcon(), resourceScreen.Layout(w, state)),
		container.NewTabItemWithIcon("Vulnerabilities", theme.WarningIcon(), vulnScreen.Layout(w, state)),
	)
	tabs.SetTabLocation(container.TabLocationLeading)

	// Auto-run the selected screen's default command when switching tabs,
	// but only if a BOM file is already loaded.
	tabs.OnChanged = func(tab *container.TabItem) {
		if state.BOMFile() == "" {
			return
		}
		idx := tabs.SelectedIndex()
		if r, ok := tabRunners[idx]; ok {
			r.Activate()
		}
	}

	w.SetContent(tabs)
	w.ShowAndRun()
}
