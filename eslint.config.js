import eslint from '@eslint/js';
import eslintConfigPrettier from 'eslint-config-prettier';
import eslintPluginSonarjs from 'eslint-plugin-sonarjs';
import eslintPluginUnicorn from 'eslint-plugin-unicorn';
import vitest from 'eslint-plugin-vitest';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    // config with just ignores is the replacement for `.eslintignore`
    ignores: ['**/build/**', '**/dist/**', 'coverage', 'vitest.config.ts', 'eslint.config.js'],
  },
  eslint.configs.recommended,
  tseslint.configs.strictTypeChecked,
  eslintPluginUnicorn.configs.all,
  {
    files: ['tests/**'], // or any other pattern
    plugins: {
      vitest,
    },
    rules: {
      ...vitest.configs.recommended.rules,
    },
    languageOptions: {
      globals: {
        ...vitest.environments.env.globals,
      },
    },
  },
  eslintPluginSonarjs.configs.recommended,
  eslintConfigPrettier,
  {
    languageOptions: {
      parserOptions: {
        project: ['./tsconfig.json', './bin/tsconfig.json', './tests/tsconfig.json'],
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      '@typescript-eslint/no-unused-vars': [
        'error',
        { ignoreRestSiblings: true, argsIgnorePattern: '^_' },
      ],
      '@typescript-eslint/ban-ts-comment': ['error', { 'ts-ignore': 'allow-with-description' }],
      '@typescript-eslint/restrict-template-expressions': [
        'error',
        { allowNumber: true, allowBoolean: true, allowNullish: true },
      ],
      'sonarjs/cognitive-complexity': ['error', 30],
      'sonarjs/todo-tag': 'warn',
      'sonarjs/fixme-tag': 'warn',
      'unicorn/prevent-abbreviations': 'off',
      'unicorn/no-keyword-prefix': 'off',
      'unicorn/catch-error-name': ['error', { name: 'err' }],
      'unicorn/prefer-ternary': ['error', 'only-single-line'],
      'unicorn/no-new-array': 'off',
      'unicorn/no-array-callback-reference': 'off',
      'unicorn/filename-case': 'off',
      'unicorn/switch-case-braces': ['error', 'avoid'],
      'unicorn/import-style': 'off',
    },
  }
);
