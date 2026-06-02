using System.Buffers.Text;
using System.Security.Cryptography;

namespace KeyForge
{
    public sealed class SecretFactory
    {
        /// <summary>
        /// Creates a new SecretKey with cryptographically random data.
        /// </summary>
        public static Secret CreateRandom()
        {
            byte[] buffer = new byte[32];
            RandomNumberGenerator.Fill(buffer);
            return new Secret(buffer);
        }

        /// <summary>
        /// Creates a SecretKey by copying the provided data.
        /// The original data remains under caller's control and should be zeroed by the caller.
        /// </summary>
        /// <param name="secret">The secret data to copy (must be 32 bytes).</param>
        public static Secret FromBytes(ReadOnlySpan<byte> secret)
        {
            if (secret.Length != 32)
                throw new ArgumentException("Secret must be exactly 32 bytes.", nameof(secret));

            byte[] copy = new byte[32];
            secret.CopyTo(copy);
            return new Secret(copy);
        }

        /// <summary>
        /// Creates a SecretKey from a base64-encoded string.
        /// </summary>
        /// <param name="secret">
        /// The base64-encoded secret string. It must decode to exactly 32 bytes.
        /// </param>
        public static Secret FromBase64(string secret)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(secret);

            byte[] data = Convert.FromBase64String(secret);

            if (data.Length != 32)
            {
                CryptographicOperations.ZeroMemory(data);
                throw new ArgumentException("Decoded secret must be exactly 32 bytes.", nameof(secret));
            }

            return new Secret(data);
        }

        /// <summary>
        /// Creates a SecretKey from a base64url-encoded string.
        /// </summary>
        /// <param name="secret">
        /// The base64url-encoded secret string. It must decode to exactly 32 bytes.
        /// </param>
        public static Secret FromBase64Url(string secret)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(secret);

            byte[] data = Base64Url.DecodeFromChars(secret);

            if (data.Length != 32)
            {
                CryptographicOperations.ZeroMemory(data);
                throw new ArgumentException("Decoded secret must be exactly 32 bytes.", nameof(secret));
            }

            return new Secret(data);
        }

        /// <summary>
        /// Creates a SecretKey from a hexadecimal string.
        /// The hexadecimal string must be 64 characters long (representing 32 bytes).
        /// </summary>
        /// <param name="secret">Hex-encoded secret (must be 64 characters for 32 bytes).</param>
        public static Secret FromHex(string secret)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(secret);

            if (secret.Length != 64)
                throw new ArgumentException("Hex secret must be 64 characters (32 bytes).", nameof(secret));

            byte[] data = Convert.FromHexString(secret);
            return new Secret(data);
        }
    }
}
