/// <reference types="bun" />
import { expect, test, describe } from "bun:test";
import { CryptoEngine } from "../src/engine";

describe("CryptoEngine Raw Key Support", () => {
  const password = "mySecurePassword123!";
  const data = { secret: "raw key test data" };
  const iterations = 1000; // Use fewer iterations for faster tests

  test("generateRawKey and importRawKey", async () => {
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const rawKey = await CryptoEngine.generateRawKey(password, salt, iterations);
    expect(rawKey).toBeInstanceOf(ArrayBuffer);
    expect(rawKey.byteLength).toBe(32); // 256 bits

    const cryptoKey = await CryptoEngine.importRawKey(rawKey);
    expect(cryptoKey.type).toBe("secret");
    expect(cryptoKey.algorithm.name).toBe("AES-GCM");
  });

  test("encryptWithRawKey and decryptWithRawKey", async () => {
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const rawKey = await CryptoEngine.generateRawKey(password, salt, iterations);

    const encrypted = await CryptoEngine.encryptWithRawKey(data, rawKey, salt, iterations);
    expect(encrypted.ciphertext).toBeDefined();
    expect(encrypted.salt).toBe(CryptoEngine["arrayBufferToBase64"](salt));

    const decrypted = await CryptoEngine.decryptWithRawKey<typeof data>(encrypted, rawKey);
    expect(decrypted).toEqual(data);
  });

  test("compatibility between master password and raw key methods", async () => {
    const encrypted = await CryptoEngine.encryptData(data, password, iterations);
    const salt = new Uint8Array(CryptoEngine["base64ToArrayBuffer"](encrypted.salt));
    
    // Derive raw key manually
    const rawKey = await CryptoEngine.generateRawKey(password, salt, iterations);
    
    // Decrypt using raw key
    const decrypted = await CryptoEngine.decryptWithRawKey<typeof data>(encrypted, rawKey);
    expect(decrypted).toEqual(data);
  });

  test("instance methods work correctly", async () => {
    const engine = new CryptoEngine({ iterations });
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const rawKey = await CryptoEngine.generateRawKey(password, salt, iterations);

    const encrypted = await engine.encryptWithRawKey(data, rawKey, salt);
    expect(encrypted.iterations).toBe(iterations);

    const decrypted = await engine.decryptWithRawKey<typeof data>(encrypted, rawKey);
    expect(decrypted).toEqual(data);
  });

  test("decryptWithRawKey fails with wrong key", async () => {
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const rawKey = await CryptoEngine.generateRawKey(password, salt, iterations);
    const wrongRawKey = await CryptoEngine.generateRawKey("wrong password", salt, iterations);

    const encrypted = await CryptoEngine.encryptWithRawKey(data, rawKey, salt, iterations);

    try {
      await CryptoEngine.decryptWithRawKey(encrypted, wrongRawKey);
      expect(true).toBe(false);
    } catch (e) {
      expect((e as Error).message).toContain("Failed to decrypt data using raw key");
    }
  });
});
