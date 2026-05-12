import { expect, test } from "bun:test";
import { createLatestRequestGate } from "../web/src/lib/latest-request.ts";

type PagedPayload = {
  page: number;
  pageSize: number;
  total: number;
  rows: { id: number }[];
};

function deferred<T>(): {
  promise: Promise<T>;
  resolve: (value: T) => void;
} {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((next) => {
    resolve = next;
  });
  return { promise, resolve };
}

test("latest request gate ignores a stale page response that resolves after a newer page", async () => {
  const gate = createLatestRequestGate();
  const firstPage = deferred<PagedPayload>();
  const secondPage = deferred<PagedPayload>();
  const renderedPages: number[] = [];

  async function refreshAccounts(load: Promise<PagedPayload>) {
    const ticket = gate.begin();
    const payload = await load;
    if (!ticket.isCurrent()) return;
    renderedPages.push(payload.page);
  }

  const firstRefresh = refreshAccounts(firstPage.promise);
  const secondRefresh = refreshAccounts(secondPage.promise);

  secondPage.resolve({ page: 2, pageSize: 20, total: 40, rows: [{ id: 21 }] });
  await secondRefresh;

  firstPage.resolve({ page: 1, pageSize: 20, total: 40, rows: [{ id: 1 }] });
  await firstRefresh;

  expect(renderedPages).toEqual([2]);
});

test("latest request gate only lets the current empty-page fallback run", async () => {
  const gate = createLatestRequestGate();
  const staleEmptyPage = deferred<PagedPayload>();
  const currentPage = deferred<PagedPayload>();
  let fallbackPage: number | undefined;
  let renderedPage: number | undefined;

  async function refreshAccounts(page: number, load: Promise<PagedPayload>) {
    const ticket = gate.begin();
    const payload = await load;
    if (!ticket.isCurrent()) return;
    if (payload.rows.length === 0 && payload.total > 0 && page > 1) {
      fallbackPage = page - 1;
      return;
    }
    renderedPage = payload.page;
  }

  const staleRefresh = refreshAccounts(2, staleEmptyPage.promise);
  const currentRefresh = refreshAccounts(3, currentPage.promise);

  currentPage.resolve({ page: 3, pageSize: 20, total: 60, rows: [{ id: 41 }] });
  await currentRefresh;

  staleEmptyPage.resolve({ page: 2, pageSize: 20, total: 60, rows: [] });
  await staleRefresh;

  expect(renderedPage).toBe(3);
  expect(fallbackPage).toBeUndefined();
});
