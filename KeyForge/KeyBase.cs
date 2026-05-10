using System.Text;
using System.Security.Cryptography;
using NSec.Cryptography;

namespace KeyForge
{
    public abstract class KeyBase
    {
        protected const string Charsets = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        protected const int ChunkSize = 8;
        protected const int BaseKeyLength = 16;
        protected const int ChecksumLength = 16;

        /// <summary>
        /// Generates a random 16-character base key using the defined alphanumeric charset.
        /// </summary>
        /// <returns>
        /// A character array representing the generated base key.
        /// </returns>
        protected ReadOnlySpan<char> GetRandomBaseKey()
        {
            byte[] buffer = new byte[BaseKeyLength];
            RandomNumberGenerator.Fill(buffer);
            char[] baseKey = new char[BaseKeyLength];
            for (int i = 0; i < baseKey.Length; i++)
                baseKey[i] = Charsets[buffer[i] % Charsets.Length];
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
        protected ulong CalculateSecureChecksum(ReadOnlySpan<char> baseKey, ReadOnlySpan<byte> secret)
        {
            var hmac = MacAlgorithm.HmacSha256;

            if (secret.Length != hmac.KeySize)
                throw new ArgumentException($"The secret must be {hmac.KeySize} bytes long.");

            int maxByteSize = Encoding.UTF8.GetMaxByteCount(baseKey.Length);
            Span<byte> utf8Bytes = maxByteSize <= 1024 ? stackalloc byte[maxByteSize] : new byte[maxByteSize];

            int bytesWritten = Encoding.UTF8.GetBytes(baseKey, utf8Bytes);
            ReadOnlySpan<byte> dataToHash = utf8Bytes.Slice(0, bytesWritten);

            using Key k = Key.Import(hmac, secret, KeyBlobFormat.RawSymmetricKey);
            ReadOnlySpan<byte> hash = hmac.Mac(k, dataToHash);

            return BitConverter.ToUInt64(hash);
        }

        /// <summary>
        /// Combines the base key and checksum into a formatted key string divided into 8-character chunks separated by hyphens.
        /// </summary>
        /// <param name="baseKey">The 16-character base key.</param>
        /// <param name="checksum">The 64-bit checksum value associated with the base key.</param>
        /// <returns>
        /// A formatted key string (e.g. "ABCD1234-EFGH5678-9ABCDEF0-12345678").
        /// </returns>
        protected string GenerateKey(ReadOnlySpan<char> baseKey, ulong checksum)
        {
            StringBuilder keyBuilder = new StringBuilder();
            for (int i = 0; i < baseKey.Length; i++)
            {
                keyBuilder.Append(baseKey[i]);
                if ((i + 1) % ChunkSize == 0 && i != baseKey.Length - 1)
                    keyBuilder.Append('-');
            }

            keyBuilder.Append('-');
            string checksumHex = checksum.ToString("X16");
            for (int j = 0; j < checksumHex.Length; j++)
            {
                keyBuilder.Append(checksumHex[j]);
                if ((j + 1) % ChunkSize == 0 && j != checksumHex.Length - 1)
                    keyBuilder.Append('-');
            }
            return keyBuilder.ToString();
        }
    }
}
