import type {
  CryptoEngineOptions,
  EncryptedData,
  PasswordStrength,
  BatchOptions
} from "./types";
import { pMap } from "./utils";

export class CryptoEngine {
  private static readonly ALGORITHM = "AES-GCM";
  private static readonly PBKDF2_ITERATIONS = 600000;
  private static readonly SALT_LENGTH = 32;
  private static readonly IV_LENGTH = 12;
  private static readonly KEY_LENGTH = 256;

  private readonly options: Required<CryptoEngineOptions>;

  constructor(options: CryptoEngineOptions = {}) {
    this.options = {
      iterations: options.iterations || CryptoEngine.PBKDF2_ITERATIONS
    };
  }

  private static arrayBufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
    const bytes =
      buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i] || 0);
    }
    return btoa(binary);
  }

  private static base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  static async hashPassword(
    password: string,
    pepper: string = ""
  ): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(password + pepper);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  static async deriveKeyFromPassword(
    password: string,
    salt: Uint8Array,
    iterations: number = CryptoEngine.PBKDF2_ITERATIONS
  ): Promise<CryptoKey> {
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);

    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      passwordBuffer,
      "PBKDF2",
      false,
      ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt as BufferSource,
        iterations: iterations,
        hash: "SHA-256"
      },
      keyMaterial,
      { name: "AES-GCM", length: this.KEY_LENGTH },
      false,
      ["encrypt", "decrypt"]
    );
  }

  static async encryptData(
    data: unknown,
    masterPassword: string,
    iterations: number = this.PBKDF2_ITERATIONS
  ): Promise<EncryptedData> {
    if (!masterPassword || masterPassword.length < 8) {
      throw new Error("Master password must be at least 8 characters long.");
    }

    let plaintext: string;
    try {
      plaintext = typeof data === "string" ? data : JSON.stringify(data);
    } catch {
      throw new Error("Failed to serialize data for encryption.");
    }

    const plaintextBytes = new TextEncoder().encode(plaintext);
    const salt = crypto.getRandomValues(new Uint8Array(this.SALT_LENGTH));
    const key = await this.deriveKeyFromPassword(
      masterPassword,
      salt,
      iterations
    );
    
    const iv = crypto.getRandomValues(new Uint8Array(this.IV_LENGTH));

    const encryptedBuffer = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
        tagLength: 128
      },
      key,
      plaintextBytes
    );

    const encryptedArray = new Uint8Array(encryptedBuffer);
    const totalLen = encryptedArray.length;
    const ciphertext = new Uint8Array(encryptedBuffer, 0, totalLen - 16);
    const authTag = new Uint8Array(encryptedBuffer, totalLen - 16, 16);

    return {
      ciphertext: this.arrayBufferToBase64(ciphertext),
      iv: this.arrayBufferToBase64(iv),
      salt: this.arrayBufferToBase64(salt),
      authTag: this.arrayBufferToBase64(authTag),
      iterations,
      version: 1
    };
  }

  async encryptData(
    data: unknown,
    masterPassword: string
  ): Promise<EncryptedData> {
    return CryptoEngine.encryptData(data, masterPassword, this.options.iterations);
  }

  // =========================================================================
  // BATCH ENCRYPTION / DECRYPTION LOGIC
  // =========================================================================

  /**
   * Encrypts a batch of items concurrently.
   * Generates a single salt and derives a single key for the entire batch to maximize performance.
   * 
   * @param items Array of data items to encrypt
   * @param masterPassword The password to encrypt the data with
   * @param iterations (Optional) The number of PBKDF2 iterations to use
   * @param options (Optional) Batch processing options (e.g., concurrency limit)
   */
  static async encryptBatch(
    items: unknown[],
    masterPassword: string,
    iterations: number = CryptoEngine.PBKDF2_ITERATIONS,
    options?: BatchOptions
  ): Promise<EncryptedData[]> {
    if (!items || items.length === 0) return [];

    const salt = crypto.getRandomValues(
      new Uint8Array(CryptoEngine.SALT_LENGTH)
    );
    const key = await CryptoEngine.deriveKeyFromPassword(
      masterPassword,
      salt,
      iterations
    );

    return pMap(
      items,
      async (item) => {
        const iv = crypto.getRandomValues(
          new Uint8Array(CryptoEngine.IV_LENGTH)
        );

        const encryptedBuffer = await crypto.subtle.encrypt(
          { name: CryptoEngine.ALGORITHM, iv },
          key,
          new TextEncoder().encode(JSON.stringify(item))
        );

        const authTag = encryptedBuffer.slice(-16);
        const ciphertext = encryptedBuffer.slice(0, -16);

        return {
          ciphertext: Buffer.from(ciphertext).toString("base64"),
          iv: Buffer.from(iv).toString("base64"),
          salt: Buffer.from(salt).toString("base64"),
          authTag: Buffer.from(authTag).toString("base64"),
          iterations
        };
      },
      options
    );
  }

  async encryptBatch(
    items: unknown[],
    masterPassword: string,
    options?: BatchOptions
  ): Promise<EncryptedData[]> {
    return CryptoEngine.encryptBatch(items, masterPassword, this.options.iterations, options);
  }

  /**
   * Decrypts a batch of items concurrently.
   * Groups items by salt/iterations to derive the key only once per unique group.
   * 
   * @param encryptedItems Array of EncryptedData items
   * @param masterPassword The password used for encryption
   * @param options (Optional) Batch processing options (e.g., concurrency limit)
   */
  static async decryptBatch<T = unknown>(
    encryptedItems: EncryptedData[],
    masterPassword: string,
    options?: BatchOptions
  ): Promise<T[]> {
    if (!encryptedItems || encryptedItems.length === 0) return [];

    // Group items by salt and iterations to minimize key derivations
    // We use a string key: `${saltBase64}_${iterations}`
    const groups = new Map<string, { keyPromise: Promise<CryptoKey>; items: { item: EncryptedData, index: number }[] }>();

    for (let i = 0; i < encryptedItems.length; i++) {
      const item = encryptedItems[i];
      const iterations = item.iterations || CryptoEngine.PBKDF2_ITERATIONS;
      const groupKey = `${item.salt}_${iterations}`;

      if (!groups.has(groupKey)) {
        const saltBuffer = Buffer.from(item.salt, "base64");
        // Start promise immediately but store it
        const keyPromise = CryptoEngine.deriveKeyFromPassword(masterPassword, saltBuffer, iterations);
        groups.set(groupKey, { keyPromise, items: [] });
      }

      groups.get(groupKey)!.items.push({ item, index: i });
    }

    const results: T[] = new Array(encryptedItems.length);

    // Process each group concurrently using pMap if there are many items per group
    await pMap(
      Array.from(groups.values()),
      async (group) => {
        const key = await group.keyPromise;
        const groupResults = await pMap(
          group.items,
          async ({ item, index }) => {
            const ivBuffer = Buffer.from(item.iv, "base64");
            const ciphertextBuffer = Buffer.from(item.ciphertext, "base64");
            const authTagBuffer = Buffer.from(item.authTag, "base64");

            // Reconstruct the encrypted payload (ciphertext + authTag)
            const encryptedDataBuffer = new Uint8Array(
              ciphertextBuffer.length + authTagBuffer.length
            );
            encryptedDataBuffer.set(ciphertextBuffer, 0);
            encryptedDataBuffer.set(authTagBuffer, ciphertextBuffer.length);

            try {
              const decryptedBuffer = await crypto.subtle.decrypt(
                { name: CryptoEngine.ALGORITHM, iv: ivBuffer },
                key,
                encryptedDataBuffer
              );
              return { index, value: JSON.parse(new TextDecoder().decode(decryptedBuffer)) as T };
            } catch (error) {
              throw new Error(`Failed to decrypt data at index ${index}. Incorrect password or corrupted data.`);
            }
          },
          options
        );
        
        // Place results back in original order
        for (const res of groupResults) {
          results[res.index] = res.value;
        }
      },
      // We run groups sequentially or concurrently, but typically there's only 1 group
      { concurrency: options?.concurrency ?? Infinity }
    );

    return results;
  }

  async decryptBatch<T = unknown>(
    encryptedItems: EncryptedData[],
    masterPassword: string,
    options?: BatchOptions
  ): Promise<T[]> {
    return CryptoEngine.decryptBatch(encryptedItems, masterPassword, options);
  }

  // =========================================================================
  // SINGLE ITEM ENCRYPTION / DECRYPTION LOGIC
  // =========================================================================

  static async decryptData<T = unknown>(
    encryptedData: EncryptedData,
    masterPassword: string
  ): Promise<T> {
    if (!masterPassword) {
      throw new Error("Master password is required for decryption.");
    }

    const salt = new Uint8Array(this.base64ToArrayBuffer(encryptedData.salt));
    const iv = new Uint8Array(this.base64ToArrayBuffer(encryptedData.iv));
    const ciphertext = new Uint8Array(
      this.base64ToArrayBuffer(encryptedData.ciphertext)
    );
    const authTag = new Uint8Array(
      this.base64ToArrayBuffer(encryptedData.authTag)
    );

    const iterations = encryptedData.iterations || this.PBKDF2_ITERATIONS;
    const key = await this.deriveKeyFromPassword(
      masterPassword,
      salt,
      iterations
    );

    const encryptedBuffer = new Uint8Array(ciphertext.length + authTag.length);
    encryptedBuffer.set(ciphertext, 0);
    encryptedBuffer.set(authTag, ciphertext.length);

    try {
      const decryptedBuffer = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv,
          tagLength: 128
        },
        key,
        encryptedBuffer
      );

      const plaintext = new TextDecoder().decode(decryptedBuffer);
      try {
        return JSON.parse(plaintext) as T;
      } catch {
        return plaintext as unknown as T;
      }
    } catch {
      throw new Error(
        "Failed to decrypt data. Wrong password or corrupted data."
      );
    }
  }

  async decryptData<T = unknown>(
    encryptedData: EncryptedData,
    masterPassword: string
  ): Promise<T> {
    return CryptoEngine.decryptData<T>(encryptedData, masterPassword);
  }

  static async tryDecrypt(
    encryptedData: EncryptedData,
    candidatePassword: string
  ): Promise<boolean> {
    try {
      await this.decryptData(encryptedData, candidatePassword);
      return true;
    } catch {
      return false;
    }
  }

  async tryDecrypt(
    encryptedData: EncryptedData,
    candidatePassword: string
  ): Promise<boolean> {
    return CryptoEngine.tryDecrypt(encryptedData, candidatePassword);
  }

  static validatePasswordStrength(password: string): PasswordStrength {
    const feedback: string[] = [];
    let score = 0;

    if (password.length >= 8) score++;
    if (password.length >= 12) score++;
    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
    if (/\d/.test(password)) score++;
    if (/[^a-zA-Z0-9]/.test(password)) score++;

    if (password.length < 8)
      feedback.push("Password must be at least 8 characters");
    if (password.length < 12)
      feedback.push("Consider using 12+ characters for better security");
    if (!/[a-z]/.test(password) || !/[A-Z]/.test(password))
      feedback.push("Include both lowercase and uppercase letters");
    if (!/\d/.test(password)) feedback.push("Include at least one number");
    if (!/[^a-zA-Z0-9]/.test(password))
      feedback.push("Include at least one special character");

    return {
      score: Math.min(score, 4),
      feedback,
      isStrong: score >= 4
    };
  }

  static async encryptPasswordForStorage(
    password: string,
    storageSalt: Uint8Array,
    iterations: number = this.PBKDF2_ITERATIONS
  ): Promise<{ ciphertext: string; iv: string; authTag: string; iterations: number }> {
    const saltBytes = new Uint8Array([...storageSalt]);
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      saltBytes,
      "PBKDF2",
      false,
      ["deriveKey"]
    );

    const key = await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: saltBytes,
        iterations: iterations,
        hash: "SHA-256"
      },
      keyMaterial,
      { name: "AES-GCM", length: this.KEY_LENGTH },
      false,
      ["encrypt"]
    );

    const iv = crypto.getRandomValues(new Uint8Array(this.IV_LENGTH));
    const encoded = new TextEncoder().encode(password);

    const encryptedBuffer = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
        tagLength: 128
      },
      key,
      encoded
    );

    const encryptedArray = new Uint8Array(encryptedBuffer);
    const totalLen = encryptedArray.length;
    const ciphertext = new Uint8Array(encryptedBuffer, 0, totalLen - 16);
    const authTag = new Uint8Array(encryptedBuffer, totalLen - 16, 16);

    return {
      ciphertext: this.arrayBufferToBase64(ciphertext),
      iv: this.arrayBufferToBase64(iv),
      authTag: this.arrayBufferToBase64(authTag),
      iterations
    };
  }

  async encryptPasswordForStorage(
    password: string,
    storageSalt: Uint8Array
  ): Promise<{
    ciphertext: string;
    iv: string;
    authTag: string;
    iterations: number;
  }> {
    return CryptoEngine.encryptPasswordForStorage(
      password,
      storageSalt,
      this.options.iterations
    );
  }

  static async decryptPasswordFromStorage(
    encrypted: {
      ciphertext: string;
      iv: string;
      authTag: string;
      iterations?: number;
    },
    storageSalt: Uint8Array
  ): Promise<string> {
    const saltBytes = new Uint8Array([...storageSalt]);
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      saltBytes,
      "PBKDF2",
      false,
      ["deriveKey"]
    );

    const iterations = encrypted.iterations || this.PBKDF2_ITERATIONS;
    const key = await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: saltBytes,
        iterations: iterations,
        hash: "SHA-256"
      },
      keyMaterial,
      { name: "AES-GCM", length: this.KEY_LENGTH },
      false,
      ["decrypt"]
    );

    const iv = new Uint8Array(this.base64ToArrayBuffer(encrypted.iv));
    const ciphertext = new Uint8Array(
      this.base64ToArrayBuffer(encrypted.ciphertext)
    );
    const authTag = new Uint8Array(this.base64ToArrayBuffer(encrypted.authTag));

    const encryptedBuffer = new Uint8Array(ciphertext.length + authTag.length);
    encryptedBuffer.set(ciphertext, 0);
    encryptedBuffer.set(authTag, ciphertext.length);

    try {
      const decryptedBuffer = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv,
          tagLength: 128
        },
        key,
        encryptedBuffer
      );

      return new TextDecoder().decode(decryptedBuffer);
    } catch {
      throw new Error("Failed to decrypt stored password.");
    }
  }

  async decryptPasswordFromStorage(
    encrypted: {
      ciphertext: string;
      iv: string;
      authTag: string;
      iterations?: number;
    },
    storageSalt: Uint8Array
  ): Promise<string> {
    return CryptoEngine.decryptPasswordFromStorage(encrypted, storageSalt);
  }

  static async encryptPasswordWithPin(
    password: string,
    pin: string,
    iterations: number = this.PBKDF2_ITERATIONS
  ): Promise<EncryptedData> {
    const salt = crypto.getRandomValues(new Uint8Array(this.SALT_LENGTH));
    const pinBuffer = new TextEncoder().encode(pin);

    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      pinBuffer,
      "PBKDF2",
      false,
      ["deriveKey"]
    );

    const key = await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: iterations,
        hash: "SHA-256"
      },
      keyMaterial,
      { name: "AES-GCM", length: this.KEY_LENGTH },
      false,
      ["encrypt"]
    );

    const iv = crypto.getRandomValues(new Uint8Array(this.IV_LENGTH));
    const encoded = new TextEncoder().encode(password);

    const encryptedBuffer = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
        tagLength: 128
      },
      key,
      encoded
    );

    const encryptedArray = new Uint8Array(encryptedBuffer);
    const totalLen = encryptedArray.length;
    const ciphertext = new Uint8Array(encryptedBuffer, 0, totalLen - 16);
    const authTag = new Uint8Array(encryptedBuffer, totalLen - 16, 16);

    return {
      ciphertext: this.arrayBufferToBase64(ciphertext),
      iv: this.arrayBufferToBase64(iv),
      salt: this.arrayBufferToBase64(salt),
      authTag: this.arrayBufferToBase64(authTag),
      iterations,
      version: 1
    };
  }

  async encryptPasswordWithPin(
    password: string,
    pin: string
  ): Promise<EncryptedData> {
    return CryptoEngine.encryptPasswordWithPin(password, pin, this.options.iterations);
  }

  static async decryptPasswordWithPin(
    encrypted: EncryptedData,
    pin: string
  ): Promise<string> {
    const salt = new Uint8Array(this.base64ToArrayBuffer(encrypted.salt));
    const iv = new Uint8Array(this.base64ToArrayBuffer(encrypted.iv));
    const ciphertext = new Uint8Array(
      this.base64ToArrayBuffer(encrypted.ciphertext)
    );
    const authTag = new Uint8Array(this.base64ToArrayBuffer(encrypted.authTag));

    const pinBuffer = new TextEncoder().encode(pin);
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      pinBuffer,
      "PBKDF2",
      false,
      ["deriveKey"]
    );

    const iterations = encrypted.iterations || this.PBKDF2_ITERATIONS;
    const key = await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: iterations,
        hash: "SHA-256"
      },
      keyMaterial,
      { name: "AES-GCM", length: this.KEY_LENGTH },
      false,
      ["decrypt"]
    );

    const encryptedBuffer = new Uint8Array(ciphertext.length + authTag.length);
    encryptedBuffer.set(ciphertext, 0);
    encryptedBuffer.set(authTag, ciphertext.length);

    try {
      const decryptedBuffer = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv,
          tagLength: 128
        },
        key,
        encryptedBuffer
      );

      return new TextDecoder().decode(decryptedBuffer);
    } catch {
      throw new Error("Failed to decrypt password using the provided PIN.");
    }
  }

  async decryptPasswordWithPin(
    encrypted: EncryptedData,
    pin: string
  ): Promise<string> {
    return CryptoEngine.decryptPasswordWithPin(encrypted, pin);
  }

  static async verifyPasswordAgainstData(
    candidatePassword: string,
    encryptedData: EncryptedData
  ): Promise<boolean> {
    try {
      const salt = new Uint8Array(this.base64ToArrayBuffer(encryptedData.salt));
      const iv = new Uint8Array(this.base64ToArrayBuffer(encryptedData.iv));
      const ciphertext = new Uint8Array(
        this.base64ToArrayBuffer(encryptedData.ciphertext)
      );
      const authTag = new Uint8Array(
        this.base64ToArrayBuffer(encryptedData.authTag)
      );

      const iterations = encryptedData.iterations || this.PBKDF2_ITERATIONS;

      const key = await this.deriveKeyFromPassword(
        candidatePassword,
        salt,
        iterations
      );

      const encryptedBuffer = new Uint8Array(
        ciphertext.length + authTag.length
      );
      encryptedBuffer.set(ciphertext, 0);
      encryptedBuffer.set(authTag, ciphertext.length);

      await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv,
          tagLength: 128
        },
        key,
        encryptedBuffer
      );

      return true;
    } catch {
      return false;
    }
  }

  async verifyPasswordAgainstData(
    candidatePassword: string,
    encryptedData: EncryptedData
  ): Promise<boolean> {
    return CryptoEngine.verifyPasswordAgainstData(
      candidatePassword,
      encryptedData
    );
  }

  static async verifyPasswordAgainstSamples(
    password: string,
    samples: any[]
  ): Promise<boolean> {
    if (!samples || samples.length === 0) return true;

    let attempted = 0;

    for (const item of samples) {
      if (!item.isEncrypted || !item.encryptionData || !item.content) continue;

      const encryptedData: EncryptedData = {
        ciphertext: item.content,
        iv: item.encryptionData.iv,
        salt: item.encryptionData.salt,
        authTag: item.encryptionData.authTag,
        iterations: item.encryptionData.iterations,
        version: item.encryptionData.version || 1
      };

      attempted++;
      const success = await this.verifyPasswordAgainstData(
        password,
        encryptedData
      );
      if (success) return true;
    }

    if (attempted === 0) return true;

    return false;
  }

  async verifyPasswordAgainstSamples(
    password: string,
    samples: any[]
  ): Promise<boolean> {
    return CryptoEngine.verifyPasswordAgainstSamples(password, samples);
  }
}
