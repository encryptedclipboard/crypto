export interface EncryptedData {
  ciphertext: string;
  iv: string;
  salt: string;
  authTag: string;
  iterations?: number;
  version?: number;
}

export interface CryptoEngineOptions extends BatchOptions {
  iterations?: number;
}

export interface BatchOptions {
  /** Maximum number of promises to run concurrently. Defaults to Infinity. */
  concurrency?: number;
}

export interface PasswordStrength {
  score: number;
  feedback: string[];
  isStrong: boolean;
}
