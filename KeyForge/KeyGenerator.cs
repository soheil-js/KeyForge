using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace KeyForge
{
    /// <summary>
    /// Provides high-level methods for creating and validating secure device keys
    /// using a shared secret and cryptographic checksum verification.
    /// </summary>
    public class KeyGenerator : KeyBase
    {
        private readonly Secret _secret;

        public KeyGenerator(Secret secret)
        {
            _secret = secret;
        }

        /// <summary>
        /// Creates a new formatted device key consisting of a random base key
        /// and a secure checksum derived from the provided secret.
        /// </summary>
        /// <param name="secret">
        /// The shared secret used to calculate the HMAC-SHA256 checksum.
        /// Must match the key size required by the underlying algorithm.
        /// </param>
        /// <returns>
        /// A fully formatted device key string containing both the base key and checksum.
        /// </returns>
        public string GenerateKey()
        {
            var baseKey = GetRandomBaseKey();
            var checksum = CalculateSecureChecksum(baseKey, _secret.GetBytes());
            return GenerateKey(baseKey, checksum);
        }

        /// <summary>
        /// Validates a device key by verifying its structure and checksum
        /// using the provided shared secret.
        /// </summary>
        /// <param name="key">
        /// The device key string to validate.
        /// </param>
        /// <param name="secretKey">
        /// The shared secret used to verify the checksum and confirm authenticity.
        /// </param>
        /// <returns>
        /// <c>true</c> if the key is valid and the checksum matches; otherwise, <c>false</c>.
        /// </returns>
        public bool ValidateKey(string key)
        {
            if (string.IsNullOrWhiteSpace(key))
                return false;

            ReadOnlySpan<char> keySpan = key.AsSpan();

            Span<char> buffer = keySpan.Length <= 1024
                ? stackalloc char[keySpan.Length]
                : new char[keySpan.Length];

            int len = keySpan.TrimToUpperInvariant(buffer);
            if (len == 0)
                return false;

            ReadOnlySpan<char> span = buffer.Slice(0, len);

            int numBaseChunks = BaseKeyLength / ChunkSize;
            int numChecksumChunks = ChecksumLength / ChunkSize;

            int totalChunks = numBaseChunks + numChecksumChunks;
            int expectedLength = BaseKeyLength + ChecksumLength + (totalChunks - 1);

            if (span.Length != expectedLength)
                return false;

            Span<char> baseKey = stackalloc char[BaseKeyLength];
            Span<char> checksumChars = stackalloc char[ChecksumLength];

            int pos = 0;
            int baseIndex = 0;
            int checksumIndex = 0;

            // --- Parse Base Key ---
            for (int i = 0; i < numBaseChunks; i++)
            {
                if (pos + ChunkSize > span.Length)
                    return false;

                span.Slice(pos, ChunkSize).CopyTo(baseKey.Slice(baseIndex));
                baseIndex += ChunkSize;
                pos += ChunkSize;

                if (i < numBaseChunks - 1)
                {
                    if (span[pos] != '-')
                        return false;
                    pos++;
                }
            }

            // separator between base and checksum
            if (numBaseChunks > 0 && numChecksumChunks > 0)
            {
                if (span[pos] != '-')
                    return false;
                pos++;
            }

            // --- Parse Checksum ---
            for (int i = 0; i < numChecksumChunks; i++)
            {
                if (pos + ChunkSize > span.Length)
                    return false;

                span.Slice(pos, ChunkSize).CopyTo(checksumChars.Slice(checksumIndex));
                checksumIndex += ChunkSize;
                pos += ChunkSize;

                if (i < numChecksumChunks - 1)
                {
                    if (span[pos] != '-')
                        return false;
                    pos++;
                }
            }

            if (pos != span.Length)
                return false;

            // --- Convert checksum hex -> ulong ---
            if (!ulong.TryParse(checksumChars, System.Globalization.NumberStyles.HexNumber, null, out ulong providedChecksum))
                return false;

            // --- Calculate expected checksum ---
            ulong calculatedChecksum = CalculateSecureChecksum(baseKey, _secret.GetBytes());

            // --- Constant-time compare ---
            Span<byte> a = stackalloc byte[sizeof(ulong)];
            Span<byte> b = stackalloc byte[sizeof(ulong)];

            MemoryMarshal.Write(a, calculatedChecksum);
            MemoryMarshal.Write(b, providedChecksum);

            return CryptographicOperations.FixedTimeEquals(a, b);
        }
    }
}
