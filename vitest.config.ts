import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    testTimeout: 30000,
    include: ['server/**/*.test.ts'],
    setupFiles: ['server/test-setup.ts'],
  },
});
