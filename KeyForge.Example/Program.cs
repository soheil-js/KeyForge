using KeyForge;

Console.Title = "KeyForge Example";

while (true)
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

    Console.ReadKey();
    Console.Clear();
}