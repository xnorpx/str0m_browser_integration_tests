/**
 * Cross-platform Karma launcher plugin for Microsoft Edge (Chromium) in headless mode.
 *
 * Detects the Edge binary on Windows, macOS, and Linux.
 * Uses Chromium-style flags for headless operation and WebRTC loopback support.
 *
 * Usage in karma.conf.js:
 *   plugins: [require('./plugins/karma-edge-launcher')]
 *   browsers: ['EdgeHeadless']
 */
'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');

/**
 * Find the Edge binary path based on the current OS.
 * Returns null if Edge is not found.
 */
function findEdgeBinary() {
  const platform = os.platform();

  if (platform === 'win32') {
    // Windows: check common installation paths.
    const candidates = [
      path.join(process.env['PROGRAMFILES(X86)'] || 'C:\\Program Files (x86)',
        'Microsoft', 'Edge', 'Application', 'msedge.exe'),
      path.join(process.env['PROGRAMFILES'] || 'C:\\Program Files',
        'Microsoft', 'Edge', 'Application', 'msedge.exe'),
      path.join(process.env.LOCALAPPDATA || '', 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
    ];
    for (const c of candidates) {
      if (fs.existsSync(c)) return c;
    }
    return null;
  }

  if (platform === 'darwin') {
    // macOS: standard application path.
    const candidates = [
      '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
      path.join(os.homedir(), 'Applications', 'Microsoft Edge.app', 'Contents', 'MacOS', 'Microsoft Edge'),
    ];
    for (const c of candidates) {
      if (fs.existsSync(c)) return c;
    }
    return null;
  }

  // Linux: check common binary names.
  const candidates = [
    '/usr/bin/microsoft-edge-stable',
    '/usr/bin/microsoft-edge',
    '/usr/bin/microsoft-edge-dev',
    '/usr/bin/microsoft-edge-beta',
  ];
  for (const c of candidates) {
    if (fs.existsSync(c)) return c;
  }
  return null;
}

/**
 * Karma browser launcher for Edge Headless.
 */
function EdgeHeadlessBrowser(baseBrowserDecorator, logger) {
  baseBrowserDecorator(this);

  const log = logger.create('launcher:EdgeHeadless');
  const edgeBin = process.env.EDGE_BINARY || findEdgeBinary();

  if (!edgeBin) {
    log.error(
      'Microsoft Edge not found! Set EDGE_BINARY env var or install Edge.\n' +
      '  Windows: Built-in or https://www.microsoft.com/edge\n' +
      '  macOS:   brew install --cask microsoft-edge\n' +
      '  Linux:   https://packages.microsoft.com/repos/edge/'
    );
  }

  this.name = 'EdgeHeadless';

  this._getCommand = function () {
    return edgeBin || 'microsoft-edge';
  };

  this._getOptions = function (url) {
    // Base flags for headless WebRTC operation.
    const baseFlags = [
      // Use a temp profile for isolation.
      `--user-data-dir=${this._tempDir}`,
      // Headless mode.
      '--headless',
      '--disable-gpu',
      // Disable first-run / default browser prompts.
      '--no-first-run',
      '--no-default-browser-check',
      '--disable-default-apps',
      '--disable-popup-blocking',
      '--disable-translate',
      // WebRTC: allow loopback candidates and disable mDNS obfuscation.
      '--disable-features=WebRtcHideLocalIpsWithMdns',
      // Prevent throttling (important for accurate timing).
      '--disable-background-timer-throttling',
      '--disable-renderer-backgrounding',
      // Sandbox / GPU workarounds for CI.
      '--no-sandbox',
      '--disable-dev-shm-usage',
      '--disable-gpu-sandbox',
      // Allow autoplay.
      '--autoplay-policy=no-user-gesture-required',
      // Remote debugging (useful for troubleshooting).
      '--remote-debugging-port=0',
    ];

    // Append any custom flags from custom launcher config (e.g. field trials).
    const extraFlags = this.flags || [];

    return [...baseFlags, ...extraFlags, url];
  };
}

EdgeHeadlessBrowser.prototype = {
  name: 'EdgeHeadless',
  DEFAULT_CMD: {
    linux: '/usr/bin/microsoft-edge-stable',
    darwin: '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
    win32: 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  },
  ENV_CMD: 'EDGE_BINARY',
};

EdgeHeadlessBrowser.$inject = ['baseBrowserDecorator', 'logger'];

module.exports = {
  'launcher:EdgeHeadless': ['type', EdgeHeadlessBrowser],
};
