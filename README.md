# KeyForge

**KeyForge** is a lightweight, secure, and self-contained API key generation and validation library for .NET, written in C#.  
It provides a simple, safe public API for creating and verifying tamper-resistant keys suitable for authentication, licensing, or device provisioning systems.

> All cryptographic operations are internal; consumers only interact with `KeyGenerator`.

## 🔒 Overview

- Public API: `KeyForge.KeyGenerator`  
- Internal helper class: `Utils` (not exposed outside the library)  
- Keys consist of a 16-character random base and an HMAC-SHA256-derived 8-byte checksum using a shared secret.  
- Validation uses constant-time comparison to prevent timing attacks.

## ✅ Features

- Secure random key generation (`RandomNumberGenerator`)  
- HMAC-SHA256 checksum (`NSec.Cryptography` used internally)  
- Constant-time comparison for safe validation (`CryptographicOperations.FixedTimeEquals`)  
- Minimal, easy-to-use public API (`KeyGenerator.Create` and `KeyGenerator.Validate`)  
- Fully self-contained; consumers do **not** need to install any additional packages.

## 📦 Public API

```csharp
namespace KeyForge
{
    public static class KeyGenerator
    {
        public static byte[] GetRandomSecret();
        public static string Create(ReadOnlySpan<byte> secret);
        public static bool Validate(string deviceKey, ReadOnlySpan<byte> secret);
    }
}
```

- `Create(ReadOnlySpan<byte> secret)` — Generates a new API key (string).  
- `Validate(string deviceKey, ReadOnlySpan<byte> secret)` — Validates a key with the same secret. Returns `true` if valid.  
- **Note:** `Utils` is `internal` and not intended for direct use.

## 🧩 Usage Example

```csharp
using KeyForge;
using System.Security.Cryptography;

class Program
{
    static void Main()
    {
        // Secret key shared between generator and validator
        var secret = KeyGenerator.GetRandomSecret().AsSpan();
        
        // Generate a new API key
        string key = KeyGenerator.Create(secret);
        Console.WriteLine($"Generated Key: {key}");

        // Validate the generated key
        bool isVerified = KeyGenerator.Validate(key, secret);
        Console.WriteLine($"Verification Result: {isVerified}");

        CryptographicOperations.ZeroMemory(secret);
    }
}
```

**Sample output:**
```
Generated Key: 35XAUXWG-01ZVECH5-D095D63E-CF50C65D
Verification Result: True
```

## 🛡 Security Recommendations

- Keep your `secret` safe. Do **not** hardcode in production; use environment variables or secure storage.  
- Use sufficiently long and random secrets (e.g., 32 bytes or more).  
- Treat generated keys as sensitive data; transmit over TLS and store securely if necessary.  
- All cryptographic operations are internal; consumers only use the public API.

## 📜 License

This project is licensed under the **MIT License**. See the included `LICENSE` file for details.
