import { expect, test } from "bun:test";

import { normalizeJobMaxAttempts } from "../src/storage/app-db";
import { jobToDraft, normalizeJobDraft, normalizeMaxAttemptsForNeed } from "../web/src/lib/job-draft";

test("backend max-attempt normalization raises under-budget jobs to 1.5x need", () => {
  expect(normalizeJobMaxAttempts(2, 1)).toBe(3);
  expect(normalizeJobMaxAttempts(3, 1)).toBe(5);
  expect(normalizeJobMaxAttempts(10, 4)).toBe(15);
  expect(normalizeJobMaxAttempts(10, 10)).toBe(10);
  expect(normalizeJobMaxAttempts(10, 12)).toBe(12);
});

test("frontend draft normalization matches backend attempt budgeting", () => {
  expect(normalizeMaxAttemptsForNeed(2, 1)).toBe(3);
  expect(
    normalizeJobDraft({
      runMode: "headed",
      need: 2,
      parallel: 2,
      maxAttempts: 1,
      autoExtractSources: [],
      autoExtractQuantity: 1,
      autoExtractMaxWaitSec: 60,
      autoExtractAccountType: "outlook",
    }).maxAttempts,
  ).toBe(3);
});

test("job snapshot drafts preserve the normalized max-attempt budget", () => {
  expect(
    jobToDraft({
      id: 113,
      status: "running",
      runMode: "headed",
      need: 2,
      parallel: 2,
      maxAttempts: 3,
      successCount: 0,
      failureCount: 0,
      skipCount: 0,
      launchedCount: 0,
      autoExtractSources: [],
      autoExtractQuantity: 0,
      autoExtractMaxWaitSec: 0,
      autoExtractAccountType: "outlook",
      startedAt: "2026-03-27T00:00:00.000Z",
      pausedAt: null,
      completedAt: null,
      lastError: null,
    }).maxAttempts,
  ).toBe(3);
});
