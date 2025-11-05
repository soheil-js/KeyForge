using KeyForge;
using System.Security.Cryptography;

while (true)
{
    // Secret key shared between generator and validator
    using SecretKey secretKey = SecretKey.CreateRandom();

    // Generate a new API key
    string key = KeyGenerator.Create(secretKey.AsSpan());
    Console.WriteLine($"Generated Key: {key}");

    // Validate the generated key
    bool isVerified = KeyGenerator.Validate(key, secretKey.AsSpan());
    Console.WriteLine($"Verification Result: {isVerified}");

    Console.ReadKey();
    Console.Clear();
}