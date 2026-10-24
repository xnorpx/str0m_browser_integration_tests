const baseConfig = require('./karma.conf');

module.exports = function (config) {
  baseConfig(config);
  config.set({
    // This suite uses native Chromium launchers, not the Safari WebDriver plugin
    // (which also registers and shadows ChromeHeadless).
    plugins: config.plugins.filter(plugin => plugin !== 'karma-local-wd-launcher'),
    files: [
      {pattern: 'src/webrtc-video.spec.ts', watched: true},
      {pattern: 'src/webrtc-frame.spec.ts', watched: true},
    ],
    client: {
      ...config.client,
      jasmine: {random: false, timeoutInterval: 45000},
    },
  });
};
