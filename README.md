# KeyForge

**KeyForge** is a lightweight, secure, and self-contained API key generation and validation library for .NET, written in C#.  
It provides a simple, safe public API for creating and verifying tamper-resistant keys suitable for authentication, licensing, or device provisioning systems.

## ✅ Features
KeyForge securely creates and validates device keys using a shared secret and cryptographic checksum.

- Secure random key generation
- HMAC-SHA256 integrity verification
- Constant-time validation
- Memory zeroization for secrets
- Simple, high-level API

## 🧩 Usage Example

```csharp
using KeyForge;

class Program
{
    static void Main()
    {
        // Secret key shared between generator and validator
        using SecretKey secretKey = SecretKey.CreateRandom();
        
        // Generate a new API key
        string key = KeyGenerator.Create(secretKey.AsSpan());
        Console.WriteLine($"Generated Key: {key}");

        // Validate the generated key
        bool isVerified = KeyGenerator.Validate(key, secretKey.AsSpan());
        Console.WriteLine($"Verification Result: {isVerified}");
    }
}
```

**Sample output:**
```
Generated Key: 35XAUXWG-01ZVECH5-D095D63E-CF50C65D
Verification Result: True
```

## 📜 License

This project is licensed under the **MIT License**. See the included `LICENSE` file for details.

## :bookmark:Credits
- [NSec.Cryptography](https://github.com/ektrah/nsec) (A modern and easy-to-use cryptographic library for .NET based on libsodium)
