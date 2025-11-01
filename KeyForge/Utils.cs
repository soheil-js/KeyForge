using NSec.Cryptography;
using System.Security.Cryptography;
using System.Text;

namespace KeyForge
{
    internal static class Utils
    {
        private const string charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        public static char[] GetRandomBaseKey()
        {
            byte[] buffer = new byte[16];
            RandomNumberGenerator.Fill(buffer);
            char[] baseKey = new char[16];
            for (int i = 0; i < baseKey.Length; i++)
                baseKey[i] = charset[buffer[i] % charset.Length];
            return baseKey;
        }

        public static ulong CalculateSecureChecksum(char[] key, ReadOnlySpan<byte> secret)
        {
            var hmac = MacAlgorithm.HmacSha256;

            if (secret.Length < hmac.KeySize)
                throw new ArgumentException($"Secret must be at least {hmac.KeySize} bytes long.");

            using var k = Key.Import(hmac, secret, KeyBlobFormat.RawSymmetricKey);
            byte[] hash = hmac.Mac(k, Encoding.UTF8.GetBytes(new string(key)));
            return BitConverter.ToUInt64(hash, 0);
        }

        public static string GenerateKey(char[] baseKey, ulong checksum)
        {
            StringBuilder keyBuilder = new StringBuilder();
            for (int i = 0; i < baseKey.Length; i++)
            {
                keyBuilder.Append(baseKey[i]);
                if ((i + 1) % 4 == 0 && i != baseKey.Length - 1)
                    keyBuilder.Append('-');
            }
            keyBuilder.AppendFormat("-{0:X16}", checksum);
            return keyBuilder.ToString();
        }

        public static bool ValidateKey(string deviceKey, ReadOnlySpan<byte> secret)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(deviceKey)) return false;

                deviceKey = deviceKey.Trim().ToUpperInvariant();

                var parts = deviceKey.Split('-');
                if (parts.Length != 5) return false;

                string baseKey = string.Concat(parts[0], parts[1], parts[2], parts[3]);
                if (baseKey.Length != 16) return false;

                if (!ulong.TryParse(parts[4], System.Globalization.NumberStyles.HexNumber, null, out ulong providedChecksum))
                    return false;

                ulong expectedChecksum = CalculateSecureChecksum(baseKey.ToCharArray(), secret);

                var expectedBytes = BitConverter.GetBytes(expectedChecksum);
                var providedBytes = BitConverter.GetBytes(providedChecksum);
                return CryptographicOperations.FixedTimeEquals(expectedBytes, providedBytes);
            }
            catch
            {
                return false;
            }
        }
    }
}
