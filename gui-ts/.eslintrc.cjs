// SPDX-License-Identifier: Apache-2.0
/** @type {import('@typescript-eslint/utils').TSESLint.Linter.Config} */
module.exports = {
  root: true,
  env: { browser: true, es2022: true },
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
    'plugin:react-hooks/recommended',
  ],
  ignorePatterns: ['dist', 'dist-electron', 'dist-release', 'node_modules'],
  parser: '@typescript-eslint/parser',
  parserOptions: {
    ecmaVersion: 'latest',
    sourceType: 'module',
  },
  plugins: ['@typescript-eslint'],
  rules: {
    '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
    // react-hooks v5 introduced set-state-in-effect and immutability rules that
    // flag valid derived-state reset patterns; disable until codebase is migrated.
    'react-hooks/set-state-in-effect': 'off',
    'react-hooks/immutability': 'off',
  },
}
