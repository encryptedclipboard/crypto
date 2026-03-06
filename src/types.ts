export interface EncryptedData {
  ciphertext: string;
  iv: string;
  salt: string;
  authTag: string;
  version?: number;
}

export interface PasswordStrength {
  score: number;
  feedback: string[];
  isStrong: boolean;
}
