const path = require('path');

module.exports = {
  mode: 'development',
  devtool: 'inline-source-map',
  resolve: {
    extensions: ['.ts', '.js'],
  },
  module: {
    rules: [
      {
        test: /\.ts$/,
        use: 'ts-loader',
        exclude: /node_modules/,
      },
    ],
  },
  // Karma-webpack handles entry/output, but we need these for standalone builds
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: '[name].js',
  },
};
