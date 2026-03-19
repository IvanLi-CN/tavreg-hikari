import { expect, test } from "bun:test";
import { createExclusiveRunner } from "../src/server/exclusive-runner.ts";

test("createExclusiveRunner serializes overlapping tasks", async () => {
  const runExclusive = createExclusiveRunner();
  const steps: string[] = [];

  const first = runExclusive(async () => {
    steps.push("first:start");
    await new Promise((resolve) => setTimeout(resolve, 25));
    steps.push("first:end");
    return "first";
  });

  const second = runExclusive(async () => {
    steps.push("second:start");
    steps.push("second:end");
    return "second";
  });

  await expect(first).resolves.toBe("first");
  await expect(second).resolves.toBe("second");
  expect(steps).toEqual(["first:start", "first:end", "second:start", "second:end"]);
});
