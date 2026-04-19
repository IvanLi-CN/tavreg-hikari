import type { AccountQuery } from "@/lib/app-types";

export const DEFAULT_ACCOUNT_QUERY_SORT = {
  sortBy: "importedAt",
  sortDir: "desc",
} as const satisfies Pick<AccountQuery, "sortBy" | "sortDir">;

export function isDefaultAccountQuerySort(query: Pick<AccountQuery, "sortBy" | "sortDir">): boolean {
  return query.sortBy === DEFAULT_ACCOUNT_QUERY_SORT.sortBy && query.sortDir === DEFAULT_ACCOUNT_QUERY_SORT.sortDir;
}

export function createDefaultAccountQuery(overrides: Partial<AccountQuery> = {}): AccountQuery {
  return {
    q: "",
    status: "",
    hasApiKey: "",
    sessionStatus: "",
    mailboxStatus: "",
    groupName: "",
    sortBy: DEFAULT_ACCOUNT_QUERY_SORT.sortBy,
    sortDir: DEFAULT_ACCOUNT_QUERY_SORT.sortDir,
    page: 1,
    pageSize: 20,
    ...overrides,
  };
}
