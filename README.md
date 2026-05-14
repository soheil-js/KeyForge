# KeyForge

**KeyForge** is a lightweight and secure library for generating and validating API keys, helping you create and verify unique keys with ease.

## 🧩 Usage Example

```csharp
using KeyForge;

class Program
{
    static void Main()
    {
        // Secret key shared between generator and validator
        using Secret secretKey = SecretFactory.CreateRandom();
        var generator = secretKey.GetKeyGenerator();
        
        // Generate a new API key
        string key = generator.GenerateKey();
        Console.WriteLine($"Generated Key: {key}");
        
        // Validate the generated key
        bool isVerified = generator.ValidateKey(key);
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
