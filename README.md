# @encryptedclipboard/crypto

A professional-grade, unified end-to-end (E2E) encryption logic library built for the **Encrypted Clipboard Manager** ecosystem.

This package is the core encryption engine of the [Encrypted Clipboard Manager](https://encryptedclipboard.app) extension, created and maintained by [Nowshad Hossain Rahat](https://x.com/nhrdev) and the [encryptedclipboard](https://github.com/encryptedclipboard) organization.

- **Website**: [encryptedclipboard.app](https://encryptedclipboard.app)
- **X/Twitter**: [@EncryptedClip](https://x.com/@EncryptedClip)
- **Maintainers**: [Nowshad Hossain Rahat](https://github.com/nowshad-hossain-rahat), [encryptedclipboard](https://github.com/encryptedclipboard)

## 🚀 Features

- **Standardized Encryption**: Uses industry-standard **AES-256-GCM** for high-performance authenticated encryption.
- **Robust Key Derivation**: Implements **PBKDF2** with a default of **600,000 iterations** (OWASP recommendation), customizable based on security vs. performance needs.
- **Hybrid API**: Seamless support for both static utility methods and pre-configured class instances.
- **Zero Dependencies**: Built entirely on top of the native **Web Crypto API**, ensuring maximum security and a tiny footprint.
- **Unified Logic**: Shared between the server, client (web), and browser extension for consistent E2E stability.
- **Security Utilities**: Includes password strength validation, SHA-256 hashing with pepper support, and PIN-based encryption.

## 📦 Installation

This package is intended to be used within the Encrypted Clipboard Manager workspace.

```bash
bun install @encryptedclipboard/crypto
```

## 🛠 Usage

This package supports both **ES Modules (ESM)** and **CommonJS (CJS)**.

### 1. Modern ESM / TypeScript (Recommended)

Works in modern Node.js, Vite, Nuxt, React, Svelte, etc.

```typescript
import { CryptoEngine } from "@encryptedclipboard/crypto";

const masterPassword = "your-strong-master-password";
const sensibleData = { secret: "This is a secret message" };
```

#### Static Approach (One-off)
```typescript
// Encrypt
const encrypted = await CryptoEngine.encryptData(sensibleData, masterPassword);

// Decrypt
const decrypted = await CryptoEngine.decryptData(encrypted, masterPassword);
```

#### Instance Approach (Pre-configured)
```typescript
const crypto = new CryptoEngine({ iterations: 100000 });

// No need to pass iterations every time
const encrypted = await crypto.encryptData(sensibleData, masterPassword);
const decrypted = await crypto.decryptData(encrypted, masterPassword);
```

### 2. Node.js CommonJS

Works in older Node.js environments or projects using `require`.
#### Static Approach

```javascript
const { CryptoEngine } = require("@encryptedclipboard/crypto");

// Usage is the same (Async/Await)
(async () => {
  const encrypted = await CryptoEngine.encryptData({ msg: "Hi" }, "pass");
  console.log(encrypted);
})();
```

#### Instance Approach

```javascript
const { CryptoEngine } = require("@encryptedclipboard/crypto");

(async () => {
  const crypto = new CryptoEngine({ iterations: 100000 });
  const encrypted = await crypto.encryptData({ msg: "Hi" }, "pass");
  console.log(encrypted);
})();
```

### 3. Direct Browser (via CDN)

Since this library has **zero dependencies** and uses the native Web Crypto API, you can use it directly in the browser without a build step.
#### Static Approach

```html
<script type="module">
  import { CryptoEngine } from "https://esm.sh/@encryptedclipboard/crypto";

  const encrypted = await CryptoEngine.encryptData(
    "Hello world",
    "my-password"
  );
  console.log("Encrypted:", encrypted);
</script>
```

#### Instance Approach

```html
<script type="module">
  import { CryptoEngine } from "https://esm.sh/@encryptedclipboard/crypto";

  const crypto = new CryptoEngine({ iterations: 100000 });
  const encrypted = await crypto.encryptData("Hello world", "my-password");
  console.log("Encrypted:", encrypted);
</script>
```

### Password Strength Validation

```typescript
const assessment = CryptoEngine.validatePasswordStrength("MyP@ssw0rd");
console.log(assessment.isStrong); // boolean
console.log(assessment.feedback); // Array of suggestions
```

### High-Performance Batch Processing

When encrypting or decrypting multiple items, use the batch methods. They automatically cache the derived key (salt) for the entire batch and use a builtin concurrency controller, drastically improving performance compared to a simple `Promise.all`.

#### Static Approach

```typescript
const items = [{ id: 1 }, { id: 2 }, { id: 3 }];

// Encrypt multiple items iteratively with a concurrency limit
const encryptedBatch = await CryptoEngine.encryptBatch(
  items, 
  "master-password", 
  600000, 
  { concurrency: 5 }
);

// Decrypt the batch
const decryptedBatch = await CryptoEngine.decryptBatch(
  encryptedBatch, 
  "master-password", 
  { concurrency: 5 }
);
```

#### Instance Approach

```typescript
const crypto = new CryptoEngine({ iterations: 100000, concurrency: 5 });
const items = [{ id: 1 }, { id: 2 }, { id: 3 }];

const encryptedBatch = await crypto.encryptBatch(items, "master-password");
const decryptedBatch = await crypto.decryptBatch(encryptedBatch, "master-password");
```

### PIN-based Encryption

Useful for local sessions where you want to lock data with a short PIN without re-entering the main password.

#### Static Approach

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

#### Instance Approach

```typescript
const crypto = new CryptoEngine({ iterations: 50000 });

const encryptedPassword = await crypto.encryptPasswordWithPin("master-password", "1234");
const originalPassword = await crypto.decryptPasswordWithPin(encryptedPassword, "1234");
```

## 🔐 Security Specifications

- **Algorithm**: `AES-GCM` (Advanced Encryption Standard - Galois/Counter Mode)
- **Key Length**: 256 bits
- **KDF**: `PBKDF2` (Password-Based Key Derivation Function 2)
- **Hash**: `SHA-256`
- **Iterations**: 600,000 (Default, Customizable)
- **Salt Length**: 256 bits (32 bytes)
- **IV Length**: 96 bits (12 bytes)

## 🛠 Development

If you want to contribute or verify the library logic locally:

1. **Clone the repo**:
   ```bash
   git clone https://github.com/encryptedclipboard/crypto.git
   ```
2. **Install dependencies**:
   ```bash
   bun install
   ```
3. **Run tests**:
   ```bash
   bun test
   ```

## 📜 License

This project is licensed under the **Apache License 2.0**.
