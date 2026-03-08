/**
 * Karma configuration for browser ↔ Pion server integration tests.
 *
 * Uses the pion-server plugin to build and launch the Go Pion server,
 * then runs the same style of data channel echo tests as the str0m tests.
 *
 * Usage:
 *   npm run test:pion:chrome     # Chrome only
 *   npm run test:pion:firefox    # Firefox only
 *   npm run test:pion:edge       # Edge only
 */

const webpackConfig = require('./webpack.config');

module.exports = function (config) {
    config.set({
        frameworks: ['pion-server', 'jasmine', 'webpack'],

        plugins: [
            'karma-jasmine',
            'karma-webpack',
            'karma-chrome-launcher',
            'karma-firefox-launcher',
            require('./plugins/karma-pion-server'),
            require('./plugins/karma-edge-launcher'),
        ],

        files: [
            { pattern: 'src/webrtc-pion.spec.ts', watched: true },
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
        },
    });

    // Replace generic browser names with WebRTC-configured variants
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
