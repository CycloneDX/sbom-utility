// SPDX-License-Identifier: Apache-2.0

package screens

import "sync"

// Runner is implemented by any screen that can auto-execute when its tab is
// selected.  main.go uses this to trigger a default run on tab-switch.
type Runner interface {
	// Activate executes the screen's default command if a BOM file is loaded.
	// It is a no-op when no file has been selected yet.
	Activate()
}

// BOMInfo carries the metadata extracted from a loaded BOM file that is
// displayed in the status bar.
type BOMInfo struct {
	// SpecVersion is the CycloneDX specVersion declared in the BOM (e.g. "1.5").
	SpecVersion string
	// FilePath is the absolute path of the loaded file.
	FilePath string
}

// AppState holds application-wide state that is shared across all screens.
type AppState struct {
	mu      sync.RWMutex
	bomFile string

	// listeners is called whenever the BOM file path changes.
	listeners []func(string)

	// bomInfo and its listeners carry the richer metadata available after
	// the BOM has been parsed (format + version detection).
	bomInfo         BOMInfo
	infoListeners   []func(BOMInfo)
}

// NewAppState creates a zero-value AppState.
func NewAppState() *AppState { return &AppState{} }

// SetBOMFile stores a new BOM file path and notifies all registered listeners.
func (s *AppState) SetBOMFile(path string) {
	s.mu.Lock()
	s.bomFile = path
	cbs := make([]func(string), len(s.listeners))
	copy(cbs, s.listeners)
	s.mu.Unlock()

	for _, cb := range cbs {
		cb(path)
	}
}

// BOMFile returns the current BOM file path.
func (s *AppState) BOMFile() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bomFile
}

// OnBOMFileChange registers a callback that is invoked (on the caller's goroutine)
// whenever the BOM file path changes.  It is called immediately with the current
// value so that newly-created screens are initialised correctly.
func (s *AppState) OnBOMFileChange(cb func(string)) {
	s.mu.Lock()
	s.listeners = append(s.listeners, cb)
	current := s.bomFile
	s.mu.Unlock()
	cb(current)
}

// SetBOMInfo stores parsed BOM metadata and notifies registered info listeners.
func (s *AppState) SetBOMInfo(info BOMInfo) {
	s.mu.Lock()
	s.bomInfo = info
	cbs := make([]func(BOMInfo), len(s.infoListeners))
	copy(cbs, s.infoListeners)
	s.mu.Unlock()

	for _, cb := range cbs {
		cb(info)
	}
}

// BOMInfoValue returns the current BOMInfo snapshot.
func (s *AppState) BOMInfoValue() BOMInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bomInfo
}

// OnBOMInfoChange registers a callback invoked whenever BOM metadata changes.
// It is called immediately with the current value.
func (s *AppState) OnBOMInfoChange(cb func(BOMInfo)) {
	s.mu.Lock()
	s.infoListeners = append(s.infoListeners, cb)
	current := s.bomInfo
	s.mu.Unlock()
	cb(current)
}
