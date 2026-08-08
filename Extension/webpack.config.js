const path               = require("path");
const CopyPlugin         = require("copy-webpack-plugin");
const MiniCssExtractPlugin = require("mini-css-extract-plugin");

module.exports = {
  entry: {
    popup:      "./src/popup/index.jsx",
    background: "./src/background/service-worker.js",
    content:    "./src/content/content-script.js",
  },
  output: {
    path:     path.resolve(__dirname, "dist"),
    filename: "[name].js",
    clean:    true,
  },
  module: {
    rules: [
      {
        test:    /\.(js|jsx)$/,
        exclude: /node_modules/,
        use:     "babel-loader",
      },
      {
        test: /\.css$/,
        use:  [MiniCssExtractPlugin.loader, "css-loader"],
      },
    ],
  },
  resolve: { extensions: [".js", ".jsx"] },
  plugins: [
    new MiniCssExtractPlugin({ filename: "[name].css" }),
    new CopyPlugin({
      patterns: [
        { from: "public",  to: "." },
        { from: "manifest.json", to: "manifest.json" },
      ],
    }),
  ],
};
