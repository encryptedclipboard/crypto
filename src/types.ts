export interface EncryptedData {
  ciphertext: string;
  iv: string;
  salt: string;
  authTag: string;
  iterations?: number;
  version?: number;
}

export interface CryptoEngineOptions {
  iterations?: number;
}

export interface PasswordStrength {
  score: number;
  feedback: string[];
  isStrong: boolean;
}
