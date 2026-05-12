export type LatestRequestTicket = {
  readonly id: number;
  isCurrent: () => boolean;
};

export function createLatestRequestGate(initialId = 0): {
  begin: () => LatestRequestTicket;
  getCurrentId: () => number;
} {
  let currentId = initialId;

  return {
    begin: () => {
      currentId += 1;
      const id = currentId;
      return {
        id,
        isCurrent: () => id === currentId,
      };
    },
    getCurrentId: () => currentId,
  };
}
