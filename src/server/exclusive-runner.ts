export type ExclusiveTask<T> = () => Promise<T>;

export function createExclusiveRunner(): <T>(task: ExclusiveTask<T>) => Promise<T> {
  let tail: Promise<void> = Promise.resolve();

  return async function runExclusive<T>(task: ExclusiveTask<T>): Promise<T> {
    const previous = tail;
    let release!: () => void;
    tail = new Promise<void>((resolve) => {
      release = resolve;
    });

    await previous;
    try {
      return await task();
    } finally {
      release();
    }
  };
}
