// SPDX-License-Identifier: Apache-2.0
/// <reference types="vite/client" />

// Expose the bridge type to the renderer so TypeScript knows about window.sbomBridge
import type { SbomBridge } from '../../preload/index'

declare global {
  interface Window {
    sbomBridge: SbomBridge
  }
}
