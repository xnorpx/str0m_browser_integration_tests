/**
 * Karma configuration for str0m browser integration tests.
 *
 * Plugins:
 *   - karma-str0m-server: Builds and launches the Rust test server.
 *   - karma-chrome-launcher: Chrome Headless launcher.
 *   - karma-edge-launcher: Cross-platform Edge Headless launcher.
 *   - karma-firefox-launcher: Firefox Headless launcher.
 *   - karma-jasmine: Test framework.
 *   - karma-webpack: TypeScript bundling.
 *
 * Usage:
 *   npm test                    # Run with all available browsers
 *   npm run test:chrome         # Chrome only
 *   npm run test:firefox        # Firefox only
 *   npm run test:edge           # Edge only
 *   npx karma start --no-single-run  # Watch mode
 */

const webpackConfig = require('./webpack.config');

module.exports = function (config) {
  config.set({
    frameworks: ['str0m-server', 'jasmine', 'webpack'],

    plugins: [
      'karma-jasmine',
      'karma-webpack',
      'karma-chrome-launcher',
      'karma-firefox-launcher',
      require('./plugins/karma-str0m-server'),
      require('./plugins/karma-edge-launcher'),
    ],

    files: [
      {pattern: 'src/webrtc-client.spec.ts', watched: true},
    ],

    preprocessors: {
      'src/**/*.spec.ts': ['webpack'],
    },

    webpack: {
      ...webpackConfig,
      entry: undefined,
    },

    webpackMiddleware: {
      stats: 'errors-only',
    },

    browsers: ['ChromeHeadless', 'EdgeHeadless', 'FirefoxHeadless'],

    customLaunchers: {
      ChromeHeadlessWebRTC: {
        base: 'ChromeHeadless',
        flags: [
          '--disable-features=WebRtcHideLocalIpsWithMdns',
          '--disable-background-timer-throttling',
          '--disable-renderer-backgrounding',
          '--no-sandbox',
          '--autoplay-policy=no-user-gesture-required',
        ],
      },
      FirefoxHeadlessWebRTC: {
        base: 'FirefoxHeadless',
        prefs: {
          'media.peerconnection.ice.loopback': true,
          'media.peerconnection.ice.obfuscate_host_addresses': false,
          'media.peerconnection.ice.default_address_only': true,
          'privacy.reduceTimerPrecision': false,
          'privacy.resistFingerprinting': false,
          'media.autoplay.default': 0,
        },
      },

      ChromeHeadlessSNAP: {
        base: 'ChromeHeadless',
        flags: [
          '--disable-features=WebRtcHideLocalIpsWithMdns',
          '--disable-background-timer-throttling',
          '--disable-renderer-backgrounding',
          '--no-sandbox',
          '--autoplay-policy=no-user-gesture-required',
          '--force-fieldtrials=WebRTC-Sctp-Snap/Enabled/',
        ],
      },

      ChromeHeadlessSPED: {
        base: 'ChromeHeadless',
        flags: [
          '--disable-features=WebRtcHideLocalIpsWithMdns,WebRtcPqcForDtls',
          '--disable-background-timer-throttling',
          '--disable-renderer-backgrounding',
          '--no-sandbox',
          '--autoplay-policy=no-user-gesture-required',
          '--force-fieldtrials=WebRTC-IceHandshakeDtls/Enabled/',
        ],
      },
      EdgeHeadlessSPED: {
        base: 'EdgeHeadless',
        flags: [
          '--disable-features=WebRtcPqcForDtls',
          '--force-fieldtrials=WebRTC-IceHandshakeDtls/Enabled/',
        ],
      },

      ChromeHeadlessWARP: {
        base: 'ChromeHeadless',
        flags: [
          '--disable-features=WebRtcHideLocalIpsWithMdns,WebRtcPqcForDtls',
          '--disable-background-timer-throttling',
          '--disable-renderer-backgrounding',
          '--no-sandbox',
          '--autoplay-policy=no-user-gesture-required',
          '--force-fieldtrials=WebRTC-Sctp-Snap/Enabled/WebRTC-IceHandshakeDtls/Enabled/',
        ],
      },
    },

    reporters: ['progress'],

    browserNoActivityTimeout: 60000, // 60s - cargo build can be slow first time
    browserDisconnectTimeout: 10000,
    captureTimeout: 60000,

    port: 9876,
    colors: true,
    logLevel: config.LOG_INFO,
    autoWatch: false,
    singleRun: true,
    concurrency: 1, // Run browsers sequentially to avoid port conflicts.

    client: {
      jasmine: {
        random: false, // Run tests in definition order for readability.
        timeoutInterval: 30000,
      },
    },
  });

  const browsers = config.browsers || [];
  const replacements = {
    'ChromeHeadless': 'ChromeHeadlessWebRTC',
    'FirefoxHeadless': 'FirefoxHeadlessWebRTC',
  };
  for (let i = 0; i < browsers.length; i++) {
    if (replacements[browsers[i]]) {
      browsers[i] = replacements[browsers[i]];
    }
  }
};
