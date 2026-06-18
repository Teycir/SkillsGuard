/**
 * Run a mapping function over an array of items concurrently, with a maximum concurrency limit.
 * Preserves the exact index ordering of the input items.
 * Guaranteed zero runtime dependencies.
 */
export async function runConcurrent<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T) => Promise<R>,
): Promise<readonly R[]> {
  const results: R[] = new Array<R>(items.length);
  let index = 0;

  async function worker(): Promise<void> {
    while (index < items.length) {
      const currentIdx = index;
      index++;
      const item = items[currentIdx];
      if (item !== undefined) {
        results[currentIdx] = await fn(item);
      }
    }
  }

  const workers: Promise<void>[] = [];
  const numWorkers = Math.min(limit, items.length);
  for (let i = 0; i < numWorkers; i++) {
    workers.push(worker());
  }
  await Promise.all(workers);

  return results;
}
