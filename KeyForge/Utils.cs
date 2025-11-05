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

        /// <summary>
        /// Generates a random 16-character base key using the defined alphanumeric charset.
        /// </summary>
        /// <returns>
        /// A character array representing the generated base key.
        /// </returns>
        public static char[] GetRandomBaseKey()
        {
            byte[] buffer = new byte[_baseKeyLength];
            RandomNumberGenerator.Fill(buffer);
            char[] baseKey = new char[_baseKeyLength];
            for (int i = 0; i < baseKey.Length; i++)
                baseKey[i] = _charset[buffer[i] % _charset.Length];
            return baseKey;
        }

        /// <summary>
        /// Calculates a secure 64-bit checksum (HMAC-SHA256 derived) for a given key using a shared secret.
        /// </summary>
        /// <param name="baseKey">The base key to compute the checksum for.</param>
        /// <param name="secret">The shared secret key used in HMAC-SHA256. Must match the algorithm's required key size.</param>
        /// <returns>
        /// A 64-bit unsigned integer representing the checksum derived from the input key and secret.
        /// </returns>
        /// <exception cref="ArgumentException">
        /// Thrown if the provided secret key does not match the required length.
        /// </exception>
        public static ulong CalculateSecureChecksum(char[] baseKey, ReadOnlySpan<byte> secret)
        {
            var hmac = MacAlgorithm.HmacSha256;

            if (secret.Length != hmac.KeySize)
                throw new ArgumentException($"The secret must be {hmac.KeySize} bytes long.");

            using Key k = Key.Import(hmac, secret, KeyBlobFormat.RawSymmetricKey);
            Span<byte> hash = hmac.Mac(k, Encoding.UTF8.GetBytes(new string(baseKey)));
            return BitConverter.ToUInt64(hash[..8].ToArray(), 0);
        }

        /// <summary>
        /// Combines the base key and checksum into a formatted key string divided into 8-character chunks separated by hyphens.
        /// </summary>
        /// <param name="baseKey">The 16-character base key.</param>
        /// <param name="checksum">The 64-bit checksum value associated with the base key.</param>
        /// <returns>
        /// A formatted key string (e.g. "ABCD1234-EFGH5678-9ABCDEF0-12345678").
        /// </returns>
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

        /// <summary>
        /// Validates a given device key by verifying its structure and confirming the checksum matches the expected value.
        /// </summary>
        /// <param name="deviceKey">The full key string to validate.</param>
        /// <param name="secret">The shared secret used to verify the key's integrity.</param>
        /// <returns>
        /// <c>true</c> if the key is valid and checksum matches; otherwise, <c>false</c>.
        /// </returns>
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
