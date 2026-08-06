/**
 * Karma configuration for SNAP feature tests.
 *
 * These tests enable the SNAP (SCTP Negotiation Acceleration Protocol)
 * experimental WebRTC feature via Chromium field trials and verify that
 * str0m can complete a full connection with SNAP enabled.
 *
 * Usage:
 *   npm run test:snap:chrome   # SNAP on Chrome
 */

const webpackConfig = require('./webpack.config');
const warpMode = process.env.STR0M_WARP === '1';

module.exports = function (config) {
  const chromeBaseFlags = [
    '--disable-features=WebRtcHideLocalIpsWithMdns',
    '--disable-background-timer-throttling',
    '--disable-renderer-backgrounding',
    '--no-sandbox',
    '--autoplay-policy=no-user-gesture-required',
  ];

  config.set({
    frameworks: ['str0m-server', 'jasmine', 'webpack'],

    plugins: [
      'karma-jasmine',
      'karma-webpack',
      'karma-chrome-launcher',
      require('./plugins/karma-str0m-server'),
      require('./plugins/karma-edge-launcher'),
    ],

    files: [
      { pattern: 'src/webrtc-snap.spec.ts', watched: true },
    ],

    preprocessors: {
      'src/webrtc-snap.spec.ts': ['webpack'],
    },

    webpack: {
      ...webpackConfig,
      entry: undefined,
    },

    webpackMiddleware: {
      stats: 'errors-only',
    },

    browsers: [warpMode ? 'ChromeHeadlessWARP' : 'ChromeHeadlessSNAP'],

    customLaunchers: {
      ChromeHeadlessSNAP: {
        base: 'ChromeHeadless',
        flags: [
          ...chromeBaseFlags,
          '--enable-features=WebRtcSctpSnap',
          '--force-fieldtrials=WebRTC-Sctp-Snap/Enabled/',
        ],
      },
      ChromeHeadlessWARP: {
        base: 'ChromeHeadless',
        flags: [
          ...chromeBaseFlags,
          '--enable-features=WebRtcSctpSnap',
          '--force-fieldtrials=WebRTC-IceHandshakeDtls/Enabled/WebRTC-ForceDtls13/Enabled/WebRTC-Sctp-Snap/Enabled/',
        ],
      },
      EdgeHeadlessSNAP: {
        base: 'EdgeHeadless',
        flags: [
          ...chromeBaseFlags,
          '--enable-features=WebRtcSctpSnap',
          '--force-fieldtrials=WebRTC-Sctp-Snap/Enabled/',
        ],
      },
      EdgeHeadlessWARP: {
        base: 'EdgeHeadless',
        flags: [
          ...chromeBaseFlags,
          '--enable-features=WebRtcSctpSnap',
          '--force-fieldtrials=WebRTC-IceHandshakeDtls/Enabled/WebRTC-ForceDtls13/Enabled/WebRTC-Sctp-Snap/Enabled/',
        ],
      },
    },

    reporters: ['progress'],

    browserNoActivityTimeout: 60000,
    browserDisconnectTimeout: 10000,
    captureTimeout: 60000,

    port: 9876,
    colors: true,
    logLevel: config.LOG_INFO,
    autoWatch: false,
    singleRun: true,
    concurrency: 1,

    client: {
      warpMode,
      jasmine: {
        random: false,
        timeoutInterval: 30000,
      },
    },
  });
};
