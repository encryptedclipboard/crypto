/// <reference types="bun" />
import { expect, test, describe } from "bun:test";
import { CryptoEngine } from "../src/engine";

describe("CryptoEngine Hybrid Usage", () => {
  const password = "password123!";
  const data = { message: "Hybrid Verification" };

  test("Instance uses configured iterations", async () => {
    const iterations = 10000;
    const engine = new CryptoEngine({ iterations });
    const encrypted = await engine.encryptData(data, password);
    
    expect(encrypted.iterations).toBe(iterations);
    
    const decrypted = await engine.decryptData(encrypted, password);
    expect(decrypted).toEqual(data);
  });

  test("Instance PIN encryption uses configured iterations", async () => {
    const iterations = 5000;
    const engine = new CryptoEngine({ iterations });
    const encrypted = await engine.encryptPasswordWithPin(password, "1234");
    
    expect(encrypted.iterations).toBe(iterations);
    
    const decrypted = await engine.decryptPasswordWithPin(encrypted, "1234");
    expect(decrypted).toBe(password);
  });

  test("Static methods still use default iterations if not specified", async () => {
    const encrypted = await CryptoEngine.encryptData(data, password);
    expect(encrypted.iterations).toBe(600000);
  });
});
