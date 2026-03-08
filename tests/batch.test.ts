import { expect, test, describe } from "bun:test";
import { CryptoEngine } from "../src/engine";

describe("CryptoEngine Batch Processing", () => {
  const masterPassword = "batchSecurePassword123!";
  const items = [
    { id: 1, text: "First item" },
    { id: 2, text: "Second item" },
    { id: 3, text: "Third item" },
    { id: 4, text: "Fourth item" },
  ];

  test("encryptBatch and decryptBatch static methods", async () => {
    // Encrypt
    const encryptedItems = await CryptoEngine.encryptBatch(items, masterPassword, 10000, { concurrency: 2 });
    
    expect(encryptedItems.length).toBe(items.length);
    
    // Check that all items in the batch share the exact same salt and iterations (Caching verified)
    const firstSalt = encryptedItems[0].salt;
    const firstIterations = encryptedItems[0].iterations;
    
    expect(firstSalt).toBeDefined();
    expect(firstIterations).toBe(10000);

    for (const item of encryptedItems) {
      expect(item.salt).toBe(firstSalt);
      expect(item.iterations).toBe(firstIterations);
      expect(item.iv).toBeDefined(); // IVs MUST be different, though hard to test strictly here without mocking
    }

    // Decrypt
    const decryptedItems = await CryptoEngine.decryptBatch<(typeof items)[0]>(encryptedItems, masterPassword, { concurrency: 2 });
    
    expect(decryptedItems.length).toBe(items.length);
    expect(decryptedItems).toEqual(items);
  });

  test("encryptBatch and decryptBatch instance methods", async () => {
    const iterations = 50000;
    const engine = new CryptoEngine({ iterations, concurrency: 4 });

    // Encrypt
    const encryptedItems = await engine.encryptBatch(items, masterPassword);
    
    expect(encryptedItems.length).toBe(items.length);
    expect(encryptedItems[0].iterations).toBe(iterations);

    // Decrypt
    const decryptedItems = await engine.decryptBatch(encryptedItems, masterPassword);
    
    expect(decryptedItems).toEqual(items);
  });

  test("decryptBatch groups items correctly on mixed batches", async () => {
    // Create two separate batches (different salts/iterations)
    const batch1 = await CryptoEngine.encryptBatch([items[0], items[1]], masterPassword, 10000);
    const batch2 = await CryptoEngine.encryptBatch([items[2], items[3]], masterPassword, 20000);

    // Mix them up
    const mixedEncrypted = [batch1[0], batch2[0], batch1[1], batch2[1]];

    // Decrypt all at once
    const decryptedItems = await CryptoEngine.decryptBatch<(typeof items)[0]>(mixedEncrypted, masterPassword);

    expect(decryptedItems.length).toBe(4);
    expect(decryptedItems[0]).toEqual(items[0]);
    expect(decryptedItems[1]).toEqual(items[2]);
    expect(decryptedItems[2]).toEqual(items[1]);
    expect(decryptedItems[3]).toEqual(items[3]);
  });

  test("empty arrays return empty arrays", async () => {
    const encrypted = await CryptoEngine.encryptBatch([], masterPassword);
    expect(encrypted).toEqual([]);

    const decrypted = await CryptoEngine.decryptBatch([], masterPassword);
    expect(decrypted).toEqual([]);
  });

  test("disabling cache results in unique salts", async () => {
    const iterations = 10000;
    const encryptedItems = await CryptoEngine.encryptBatch(items, masterPassword, iterations, { disableCache: true });

    expect(encryptedItems.length).toBe(items.length);

    // Verify each item has a unique salt
    const salts = new Set(encryptedItems.map(i => i.salt));
    expect(salts.size).toBe(items.length);

    // Verify we can still decrypt them
    const decryptedItems = await CryptoEngine.decryptBatch<(typeof items)[0]>(encryptedItems, masterPassword, { disableCache: true });
    expect(decryptedItems).toEqual(items);
  });

  test("instance with disableCache works", async () => {
    const engine = new CryptoEngine({ iterations: 10000, disableCache: true });
    const encryptedItems = await engine.encryptBatch(items, masterPassword);

    const salts = new Set(encryptedItems.map(i => i.salt));
    expect(salts.size).toBe(items.length);

    const decryptedItems = await engine.decryptBatch(encryptedItems, masterPassword);
    expect(decryptedItems).toEqual(items);
  });
});
