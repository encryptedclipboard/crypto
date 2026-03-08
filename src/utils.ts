import { BatchOptions } from "./types";

/**
 * A custom, enterprise-grade generic concurrency mapping utility.
 * It processes items in an array concurrently up to the specified limit.
 * 
 * @param iterable The array of items to process.
 * @param mapper The async function to apply to each item.
 * @param options Options including the `concurrency` limit.
 * @returns A promise that resolves to an array of mapped results.
 */
export async function pMap<T, R>(
  iterable: Iterable<T>,
  mapper: (item: T, index: number) => Promise<R> | R,
  options?: BatchOptions
): Promise<R[]> {
  const items = Array.from(iterable);
  const concurrency = options?.concurrency ?? Infinity;

  if (concurrency < 1) {
    throw new TypeError(`Expected \`concurrency\` to be a number from 1 and up, got \`${concurrency}\``);
  }

  const results: R[] = new Array(items.length);
  const errors: unknown[] = [];
  let currentIndex = 0;
  let activeWorkers = 0;

  return new Promise<R[]>((resolve, reject) => {
    if (items.length === 0) {
      return resolve(results);
    }

    const next = () => {
      // If there was an error in any worker, stop processing new items
      if (errors.length > 0) return;

      // If all items have been processed and no workers are active, we're done
      if (currentIndex >= items.length && activeWorkers === 0) {
        return resolve(results);
      }

      // Start new workers up to the concurrency limit
      while (activeWorkers < concurrency && currentIndex < items.length) {
        const index = currentIndex++;
        const item = items[index];
        activeWorkers++;

        Promise.resolve(mapper(item, index))
          .then((result) => {
            results[index] = result;
            activeWorkers--;
            next();
          })
          .catch((error) => {
            errors.push(error);
            reject(error); // Reject immediately on first error
          });
      }
    };

    next();
  });
}
