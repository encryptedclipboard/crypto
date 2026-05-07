export interface EncryptedData {
  ciphertext: string;
  iv: string;
  salt: string;
  authTag: string;
  iterations?: number;
  version?: number;
}

export interface CryptoEngineOptions extends Omit<BatchOptions, "onProgress"> {
  iterations?: number;
}

export interface BatchOptions {
  /** Maximum number of promises to run concurrently. Defaults to Infinity. */
  concurrency?: number;
  /** Whether to disable salt/key caching for the batch. Defaults to false. */
  disableCache?: boolean;
  /** Callback executed after each item is processed in the batch. */
  onProgress?: (processed: number, total: number) => void;
}

export interface PasswordStrength {
  score: number;
  feedback: string[];
  isStrong: boolean;
}

export interface EncryptDataOptions {
  /** Optional salt for key derivation. If not provided, a random 32-byte salt will be generated. */
  salt?: Uint8Array;
  /** Optional IV for encryption. If not provided, a random 12-byte IV will be generated. */
  iv?: Uint8Array;
  /** Number of PBKDF2 iterations. Defaults to 400000. */
  iterations?: number;
}
