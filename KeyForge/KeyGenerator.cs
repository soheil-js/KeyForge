using System.Security.Cryptography;

namespace KeyForge
{
    /// <summary>
    /// Provides high-level methods for creating and validating secure device keys
    /// using a shared secret and cryptographic checksum verification.
    /// </summary>
    public static class KeyGenerator
    {
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
        public static string Create(ReadOnlySpan<byte> secret)
        {
            char[] baseKey = Utils.GetRandomBaseKey();
            ulong checksum = Utils.CalculateSecureChecksum(baseKey, secret);
            return Utils.GenerateKey(baseKey, checksum);
        }

        /// <summary>
        /// Validates a device key by verifying its structure and checksum
        /// using the provided shared secret.
        /// </summary>
        /// <param name="deviceKey">
        /// The device key string to validate.
        /// </param>
        /// <param name="secret">
        /// The shared secret used to verify the checksum and confirm authenticity.
        /// </param>
        /// <returns>
        /// <c>true</c> if the key is valid and the checksum matches; otherwise, <c>false</c>.
        /// </returns>
        public static bool Validate(string deviceKey, ReadOnlySpan<byte> secret)
        {
            return Utils.ValidateKey(deviceKey, secret);
        }
    }
}
