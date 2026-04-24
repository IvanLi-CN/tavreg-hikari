function pad(value: number): string {
  return String(value).padStart(2, "0");
}

export function buildApiKeyExportFilename(now = new Date()): string {
  const year = now.getFullYear();
  const month = pad(now.getMonth() + 1);
  const day = pad(now.getDate());
  const hours = pad(now.getHours());
  const minutes = pad(now.getMinutes());
  const seconds = pad(now.getSeconds());
  return `tavily-api-keys-${year}${month}${day}-${hours}${minutes}${seconds}.txt`;
}

export function countMissingExportIds(
  requestedIds: ReadonlyArray<number>,
  returnedItems: ReadonlyArray<{ id: number }>,
): number {
  const normalizedRequestedIds = Array.from(
    new Set(requestedIds.filter((id) => Number.isInteger(id) && id > 0)),
  );
  if (normalizedRequestedIds.length === 0) {
    return 0;
  }
  const returnedIds = new Set(returnedItems.map((item) => item.id));
  return normalizedRequestedIds.reduce((missingCount, id) => missingCount + (returnedIds.has(id) ? 0 : 1), 0);
}
