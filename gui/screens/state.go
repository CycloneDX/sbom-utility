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

// AppState holds application-wide state that is shared across all screens.
type AppState struct {
	mu      sync.RWMutex
	bomFile string

	// listeners is called whenever the BOM file path changes.
	listeners []func(string)
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
