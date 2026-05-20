/*
 * Copyright 2025 Daytona Platforms Inc.
 * Modified by BoxLite AI, 2025-2026
 * SPDX-License-Identifier: AGPL-3.0
 */

export default {
  displayName: 'boxlite',
  preset: '../jest.preset.js',
  testEnvironment: 'node',
  transform: {
    '^.+\\.[tj]s$': ['ts-jest', { tsconfig: '<rootDir>/tsconfig.spec.json' }],
  },
  // uuid v14 and nanoid ship ESM-only. The nx preset ignores node_modules from
  // transformation, so specs importing these (directly or transitively) crash on ESM.
  // Let ts-jest down-level them.
  transformIgnorePatterns: ['/node_modules/(?!(?:uuid|nanoid)/)'],
  moduleNameMapper: {
    '@boxlite-ai/runner-api-client': '<rootDir>/../libs/runner-api-client/src/index.ts',
    '@boxlite-ai/api-client': '<rootDir>/../libs/api-client/src/index.ts',
    '@boxlite-ai/toolbox-api-client': '<rootDir>/../libs/toolbox-api-client/src/index.ts',
    '@boxlite-ai/analytics-api-client': '<rootDir>/../libs/analytics-api-client/src/index.ts',
  },
  moduleFileExtensions: ['ts', 'js', 'html'],
  coverageDirectory: '../../coverage/apps/boxlite',
}
