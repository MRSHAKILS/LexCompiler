import { useScratchFixtureCopy } from './cli/scratchFixture.js';

// Each test file works on its own copy of the demo fixture, never on target-repo/ itself.
useScratchFixtureCopy('test');
