using System.Security.Cryptography;

namespace KeyForge
{
    public static class KeyGenerator
    {
        public static byte[] GetRandomSecret()
        {
            byte[] buffer = new byte[32];
            RandomNumberGenerator.Fill(buffer);
            return buffer;
        }

        public static string Create(ReadOnlySpan<byte> secret)
        {
            char[] baseKey = Utils.GetRandomBaseKey();
            ulong checksum = Utils.CalculateSecureChecksum(baseKey, secret);
            return Utils.GenerateKey(baseKey, checksum);
        }

        public static bool Validate(string deviceKey, ReadOnlySpan<byte> secret)
        {
            return Utils.ValidateKey(deviceKey, secret);
        }
    }
}
