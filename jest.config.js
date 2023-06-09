export default {
  coverageDirectory: 'coverage',
  coverageProvider: 'v8',
  collectCoverage: true,
  testEnvironment: 'node',
  preset: 'ts-jest/presets/default-esm',
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  testRegex: 'tests/.*\\.test\\.ts',
  testTimeout: 10_000,
};
