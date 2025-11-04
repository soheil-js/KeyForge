using NSec.Cryptography;
using System.Security.Cryptography;
using System.Text;

namespace KeyForge
{
    internal static class Utils
    {
        private const string _charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        private const int _chunkSize = 8;
        private const int _baseKeyLength = 16;
        private const int _checksumLength = 16;

        public static char[] GetRandomBaseKey()
        {
            byte[] buffer = new byte[_baseKeyLength];
            RandomNumberGenerator.Fill(buffer);
            char[] baseKey = new char[_baseKeyLength];
            for (int i = 0; i < baseKey.Length; i++)
                baseKey[i] = _charset[buffer[i] % _charset.Length];
            return baseKey;
        }

        public static ulong CalculateSecureChecksum(char[] key, ReadOnlySpan<byte> secret)
        {
            var hmac = MacAlgorithm.HmacSha256;

            if (secret.Length != hmac.KeySize)
                throw new ArgumentException($"The secret must be {hmac.KeySize} bytes long.");

            using Key k = Key.Import(hmac, secret, KeyBlobFormat.RawSymmetricKey);
            Span<byte> hash = hmac.Mac(k, Encoding.UTF8.GetBytes(new string(key)));
            return BitConverter.ToUInt64(hash[..8].ToArray(), 0);
        }

        public static string GenerateKey(char[] baseKey, ulong checksum)
        {
            StringBuilder keyBuilder = new StringBuilder();
            for (int i = 0; i < baseKey.Length; i++)
            {
                keyBuilder.Append(baseKey[i]);
                if ((i + 1) % _chunkSize == 0 && i != baseKey.Length - 1)
                    keyBuilder.Append('-');
            }

            keyBuilder.Append('-');
            string checksumHex = checksum.ToString("X16");
            for (int j = 0; j < checksumHex.Length; j++)
            {
                keyBuilder.Append(checksumHex[j]);
                if ((j + 1) % _chunkSize == 0 && j != checksumHex.Length - 1)
                    keyBuilder.Append('-');
            }
            return keyBuilder.ToString();
        }

        public static bool ValidateKey(string deviceKey, ReadOnlySpan<byte> secret)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(deviceKey) || !deviceKey.Contains("-"))
                    return false;

                deviceKey = deviceKey.Trim().ToUpperInvariant();

                var parts = deviceKey.Split('-');
                const int totalLength = _baseKeyLength + _checksumLength;
                if (parts.Length != (totalLength / _chunkSize))
                    return false;

                StringBuilder baseKeyBuilder = new StringBuilder();
                StringBuilder checksumBuilder = new StringBuilder();

                for (var i = 0; i < parts.Length; i++)
                {
                    if (i < (_baseKeyLength / _chunkSize))
                        baseKeyBuilder.Append(parts[i]);
                    else
                        checksumBuilder.Append(parts[i]);
                }

                if (baseKeyBuilder.Length != _baseKeyLength || checksumBuilder.Length != _checksumLength)
                    return false;

                if (!ulong.TryParse(checksumBuilder.ToString(), System.Globalization.NumberStyles.HexNumber, null, out ulong providedChecksum))
                    return false;

                ulong expectedChecksum = CalculateSecureChecksum(baseKeyBuilder.ToString().ToCharArray(), secret);

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
