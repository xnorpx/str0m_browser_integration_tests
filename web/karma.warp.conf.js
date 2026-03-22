/**
 * Karma configuration for SNAP / WARP feature tests.
 *
 * These tests enable experimental WebRTC features via Chromium field trials
 * and verify that str0m can complete a full connection with SNAP enabled.
 *
 * Features:
 *   SNAP  - SCTP Negotiation Acceleration Protocol (WebRTC-Sctp-Snap)
 *   WARP  - SNAP + DTLS 1.3 combined
 *
 * Usage:
 *   npm run test:snap:chrome                    # SNAP on Chrome
 *   npm run test:warp:chrome                    # WARP on Chrome (SNAP + DTLS 1.3)
 *
 * Note: DTLS 1.3 (RFC 9147) is enabled by default in Chrome/Edge since
 *       Oct 2025 (issues.webrtc.org/383141571) - the base tests already
 *       exercise it when using aws-lc-rs or rust-crypto backends.
 */

const webpackConfig = require('./webpack.config');

let feature = (process.env.WARP_FEATURE || '').toLowerCase();

const FEATURE_BROWSERS = {
  snap: { chrome: 'ChromeHeadlessSNAP' },
  warp: { chrome: 'ChromeHeadlessWARP' },
};

const BROWSER_TO_FEATURE = {};
for (const [feat, map] of Object.entries(FEATURE_BROWSERS)) {
  BROWSER_TO_FEATURE[map.chrome] = feat;
  BROWSER_TO_FEATURE[map.edge] = feat;
}

module.exports = function (config) {
  let browsers = config.browsers && config.browsers.length > 0
    ? config.browsers
    : ['ChromeHeadlessWARP'];

  if (!feature) {
    feature = BROWSER_TO_FEATURE[browsers[0]] || 'warp';
  }

  const chromeBaseFlags = [
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
      { pattern: 'src/webrtc-warp.spec.ts', watched: true },
    ],

    preprocessors: {
      'src/webrtc-warp.spec.ts': ['webpack'],
    },

    webpack: {
      ...webpackConfig,
      entry: undefined,
    },

    webpackMiddleware: {
      stats: 'errors-only',
    },

    browsers,

    customLaunchers: {
      ChromeHeadlessSNAP: {
        base: 'ChromeHeadless',
        flags: [
          '--disable-features=WebRtcHideLocalIpsWithMdns',
          ...chromeBaseFlags,
          '--force-fieldtrials=WebRTC-Sctp-Snap/Enabled/',
        ],
      },
      ChromeHeadlessWARP: {
        base: 'ChromeHeadless',
        flags: [
          '--disable-features=WebRtcHideLocalIpsWithMdns,WebRtcPqcForDtls',
          ...chromeBaseFlags,
          '--force-fieldtrials=WebRTC-Sctp-Snap/Enabled/WebRTC-IceHandshakeDtls/Enabled/',
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
      jasmine: {
        random: false,
        timeoutInterval: 30000,
      },
      warpFeature: feature,
    },
  });
};
