# @encryptedclipboard/crypto

A professional-grade, unified end-to-end (E2E) encryption logic library built for the **Encrypted Clipboard Manager** ecosystem.

This package is the core encryption engine of the [Encrypted Clipboard Manager](https://encryptedclipboard.app) extension, created and maintained by [Nowshad Hossain Rahat](https://x.com/nowshadrahat) and the [encryptedclipboard](https://github.com/encryptedclipboard) organization.

- **Website**: [encryptedclipboard.app](https://encryptedclipboard.app)
- **X/Twitter**: [@EncryptedClip](https://x.com/@EncryptedClip)
- **Maintainers**: [Nowshad Hossain Rahat](https://github.com/nowshad-hossain-rahat), [encryptedclipboard](https://github.com/encryptedclipboard)

## 🚀 Features

- **Standardized Encryption**: Uses industry-standard **AES-256-GCM** for high-performance authenticated encryption.
- **Robust Key Derivation**: Implements **PBKDF2** with **600,000 iterations** and SHA-256 (following modern OWASP recommendations).
- **Zero Dependencies**: Built entirely on top of the native **Web Crypto API**, ensuring maximum security and a tiny footprint.
- **Unified Logic**: Shared between the server, client (web), and browser extension for consistent E2E stability.
- **Security Utilities**: Includes password strength validation, SHA-256 hashing with pepper support, and PIN-based encryption.

## 📦 Installation

This package is intended to be used within the Encrypted Clipboard Manager workspace.

```bash
bun install @encryptedclipboard/crypto
```

## 🛠 Usage

### Basic Encryption & Decryption

```typescript
import { CryptoEngine } from "@encryptedclipboard/crypto";

const masterPassword = "your-strong-master-password";
const sensibleData = { secret: "This is a secret message" };

// Encrypt
const encrypted = await CryptoEngine.encryptData(sensibleData, masterPassword);

// Decrypt
const decrypted = await CryptoEngine.decryptData(encrypted, masterPassword);
console.log(decrypted); // { secret: "This is a secret message" }
```

### Password Strength Validation

```typescript
const assessment = CryptoEngine.validatePasswordStrength("MyP@ssw0rd");
console.log(assessment.isStrong); // boolean
console.log(assessment.feedback); // Array of suggestions
```

### PIN-based Encryption

Useful for local sessions where you want to lock data with a short PIN without re-entering the main password.

```typescript
const encryptedPassword = await CryptoEngine.encryptPasswordWithPin(
  "master-password",
  "1234"
);
const originalPassword = await CryptoEngine.decryptPasswordWithPin(
  encryptedPassword,
  "1234"
);
```

## 🔐 Security Specifications

- **Algorithm**: `AES-GCM` (Advanced Encryption Standard - Galois/Counter Mode)
- **Key Length**: 256 bits
- **KDF**: `PBKDF2` (Password-Based Key Derivation Function 2)
- **Hash**: `SHA-256`
- **Iterations**: 600,000
- **Salt Length**: 256 bits (32 bytes)
- **IV Length**: 96 bits (12 bytes)

## 🧪 Testing

The library is fully covered by unit tests using Bun.

```bash
bun test
```

## 📜 License

This project is licensed under the **Apache License 2.0**.
