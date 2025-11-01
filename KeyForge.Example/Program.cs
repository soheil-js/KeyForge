using KeyForge;
using System.Security.Cryptography;

// Secret key shared between generator and validator
byte[] secretBytes = new byte[32];
RandomNumberGenerator.Fill(secretBytes);

// Generate a new API key
string key = KeyGenerator.Create(secretBytes);
Console.WriteLine($"Generated Key: {key}");

// Validate the generated key
bool isValid = KeyGenerator.Validate(key, secretBytes);
Console.WriteLine($"Is Valid: {isValid}");

Console.ReadKey();
