import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Server tests run in Node; UI tests (src/**/*.test.tsx) opt into jsdom with a
    // `// @vitest-environment jsdom` comment.
    environment: 'node',
    testTimeout: 30000,
    include: ['server/**/*.test.ts', 'src/**/*.test.tsx'],
    setupFiles: ['server/test-setup.ts'],
    // Builds a real compliance report (Z3 included) once, in a child process, for the UI tests.
    globalSetup: ['src/test/globalSetup.ts'],
  },
});
