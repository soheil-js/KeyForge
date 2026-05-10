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
        /// <param name="data">The secret data to copy (must be 32 bytes).</param>
        public static Secret FromBytes(ReadOnlySpan<byte> data)
        {
            if (data.Length != 32)
                throw new ArgumentException("Secret must be exactly 32 bytes.", nameof(data));

            byte[] copy = new byte[32];
            data.CopyTo(copy);
            return new Secret(copy);
        }

        /// <summary>
        /// Creates a SecretKey from a base64-encoded string.
        /// </summary>
        /// <param name="base64Secret">
        /// The base64-encoded secret string. It must decode to exactly 32 bytes.
        /// </param>
        public static Secret FromBase64(string base64Secret)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(base64Secret);

            byte[] data = Convert.FromBase64String(base64Secret);

            if (data.Length != 32)
            {
                CryptographicOperations.ZeroMemory(data);
                throw new ArgumentException("Decoded secret must be exactly 32 bytes.", nameof(base64Secret));
            }

            return new Secret(data);
        }

        /// <summary>
        /// Creates a SecretKey from a hexadecimal string.
        /// The hexadecimal string must be 64 characters long (representing 32 bytes).
        /// </summary>
        /// <param name="hexSecret">Hex-encoded secret (must be 64 characters for 32 bytes).</param>
        public static Secret FromHex(string hexSecret)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(hexSecret);

            if (hexSecret.Length != 64)
                throw new ArgumentException("Hex secret must be 64 characters (32 bytes).", nameof(hexSecret));

            byte[] data = Convert.FromHexString(hexSecret);
            return new Secret(data);
        }
    }
}
