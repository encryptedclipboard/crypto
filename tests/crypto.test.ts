/// <reference types="bun" />
import { expect, test, describe } from "bun:test";
import { CryptoEngine } from "../src/engine";

describe("CryptoEngine", () => {
  const password = "mySecurePassword123!";
  const weakPassword = "pass";
  const pin = "1234";

  test("validatePasswordStrength", () => {
    const weak = CryptoEngine.validatePasswordStrength(weakPassword);
    expect(weak.isStrong).toBe(false);

    const strong = CryptoEngine.validatePasswordStrength(password);
    expect(strong.isStrong).toBe(true);
  });

  test("hashPassword generates a string hash", async () => {
    const hash = await CryptoEngine.hashPassword(password);
    expect(typeof hash).toBe("string");
    expect(hash.length).toBeGreaterThan(0);
  });

  test("encrypt and decrypt data properly", async () => {
    const data = { secret: "hello world" };

    const encrypted = await CryptoEngine.encryptData(data, password);
    expect(typeof encrypted.ciphertext).toBe("string");
    expect(typeof encrypted.iv).toBe("string");
    expect(typeof encrypted.salt).toBe("string");
    expect(typeof encrypted.authTag).toBe("string");

    const decrypted = await CryptoEngine.decryptData(encrypted, password);
    expect(decrypted).toEqual(data);
  });

  test("decrypting with wrong password throws", async () => {
    const data = { secret: "hello world" };
    const encrypted = await CryptoEngine.encryptData(data, password);

    try {
      await CryptoEngine.decryptData(encrypted, "wrongPassword");
      expect(true).toBe(false); // Should not reach here
    } catch (e) {
      expect((e as Error).message).toContain("Failed to decrypt data");
    }
  });

  test("tryDecrypt verifies a password correctly", async () => {
    const encrypted = await CryptoEngine.encryptData("test", password);

    const isCorrect = await CryptoEngine.tryDecrypt(encrypted, password);
    expect(isCorrect).toBe(true);

    const isWrong = await CryptoEngine.tryDecrypt(encrypted, "wrongPassword");
    expect(isWrong).toBe(false);
  });

  test("encrypt and decrypt password for storage using fixed salt", async () => {
    const mockSalt = new TextEncoder().encode(
      "TEST_STORAGE_SALT_DO_NOT_CHANGE"
    );
    const encrypted = await CryptoEngine.encryptPasswordForStorage(
      password,
      mockSalt
    );
    expect(encrypted.ciphertext).toBeDefined();

    const decrypted = await CryptoEngine.decryptPasswordFromStorage(
      encrypted,
      mockSalt
    );
    expect(decrypted).toBe(password);
  });

  test("encrypt and decrypt password with pin", async () => {
    const encrypted = await CryptoEngine.encryptPasswordWithPin(password, pin);
    expect(encrypted.salt).toBeDefined();

    const decrypted = await CryptoEngine.decryptPasswordWithPin(encrypted, pin);
    expect(decrypted).toBe(password);
  });

  test("verifyPasswordAgainstData returns true for correct password", async () => {
    const data = { secret: "test" };
    const encrypted = await CryptoEngine.encryptData(data, password);
    const result = await CryptoEngine.verifyPasswordAgainstData(
      password,
      encrypted
    );
    expect(result).toBe(true);
  });

  test("verifyPasswordAgainstSamples verifies samples array correctly", async () => {
    const encryptedText = await CryptoEngine.encryptData("Sample", password);
    const validSample = {
      isEncrypted: true,
      content: encryptedText.ciphertext,
      encryptionData: {
        iv: encryptedText.iv,
        salt: encryptedText.salt,
        authTag: encryptedText.authTag,
        version: 1
      }
    };

    const isVerified = await CryptoEngine.verifyPasswordAgainstSamples(
      password,
      [validSample]
    );
    expect(isVerified).toBe(true);

    const isFailed = await CryptoEngine.verifyPasswordAgainstSamples(
      "wrongPassword",
      [validSample]
    );
    expect(isFailed).toBe(false);
  });

  test("work with short passwords", async () => {
    const shortPassword = "123";
    const data = { secret: "short" };
    const encrypted = await CryptoEngine.encryptData(data, shortPassword);
    const decrypted = await CryptoEngine.decryptData(encrypted, shortPassword);
    expect(decrypted).toEqual(data);
  });

  test("throwing error when password is missing", async () => {
    const data = { secret: "test" };
    
    // Encrypt
    try {
      await CryptoEngine.encryptData(data, "");
      expect(true).toBe(false);
    } catch (e) {
      expect((e as Error).message).toBe("Master password is required for encryption.");
    }

    // Decrypt
    const encrypted = await CryptoEngine.encryptData(data, "pass");
    try {
      await CryptoEngine.decryptData(encrypted, "");
      expect(true).toBe(false);
    } catch (e) {
      expect((e as Error).message).toBe("Master password is required for decryption.");
    }
  });
});
