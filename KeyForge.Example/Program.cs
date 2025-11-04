using KeyForge;
using System.Security.Cryptography;

while (true)
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

    Console.ReadKey();
    Console.Clear();
}