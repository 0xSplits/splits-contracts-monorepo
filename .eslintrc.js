// This configuration only applies to the package manager root.
/** @type {import("eslint").Linter.Config} */
module.exports = {
  ignorePatterns: ["packages/**"],
  extends: [],
  parser: "@typescript-eslint/parser",
  parserOptions: {
    project: true,
  },
};
