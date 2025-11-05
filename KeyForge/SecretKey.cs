using System.Security.Cryptography;

namespace KeyForge
{
    public sealed class SecretKey : IDisposable
    {
        private byte[]? _data;
        private bool _disposed;

        private SecretKey(byte[] data)
        {
            _data = data;
        }

        /// <summary>
        /// Creates a new SecretKey with cryptographically random data.
        /// </summary>
        public static SecretKey CreateRandom()
        {
            byte[] buffer = new byte[32];
            RandomNumberGenerator.Fill(buffer);
            return new SecretKey(buffer);
        }

        /// <summary>
        /// Creates a SecretKey by copying the provided data.
        /// The original data remains under caller's control and should be zeroed by the caller.
        /// </summary>
        /// <param name="data">The secret data to copy (must be 32 bytes).</param>
        public static SecretKey FromBytes(ReadOnlySpan<byte> data)
        {
            if (data.Length != 32)
                throw new ArgumentException("Secret must be exactly 32 bytes.", nameof(data));

            byte[] copy = new byte[32];
            data.CopyTo(copy);
            return new SecretKey(copy);
        }

        /// <summary>
        /// Creates a SecretKey from a base64-encoded string.
        /// </summary>
        /// <param name="base64Secret">
        /// The base64-encoded secret string. It must decode to exactly 32 bytes.
        /// </param>
        public static SecretKey FromBase64(string base64Secret)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(base64Secret);

            byte[] data = Convert.FromBase64String(base64Secret);

            if (data.Length != 32)
            {
                CryptographicOperations.ZeroMemory(data);
                throw new ArgumentException("Decoded secret must be exactly 32 bytes.", nameof(base64Secret));
            }

            return new SecretKey(data);
        }

        /// <summary>
        /// Creates a SecretKey from a hexadecimal string.
        /// The hexadecimal string must be 64 characters long (representing 32 bytes).
        /// </summary>
        /// <param name="hexSecret">Hex-encoded secret (must be 64 characters for 32 bytes).</param>
        public static SecretKey FromHex(string hexSecret)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(hexSecret);

            if (hexSecret.Length != 64)
                throw new ArgumentException("Hex secret must be 64 characters (32 bytes).", nameof(hexSecret));

            byte[] data = Convert.FromHexString(hexSecret);
            return new SecretKey(data);
        }

        /// <summary>
        /// Returns the underlying key data as a read-only byte span.
        /// </summary>
        /// <returns>
        /// A <see cref="ReadOnlySpan{Byte}"/> representing the internal key data.
        /// </returns>
        /// <exception cref="ObjectDisposedException">
        /// Thrown if the object has already been disposed.
        /// </exception>
        public ReadOnlySpan<byte> AsSpan()
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _data;
        }

        /// <summary>
        /// Securely releases all resources used by this instance.
        /// The key data is cleared from memory before disposal to prevent sensitive information leaks.
        /// </summary>
        public void Dispose()
        {
            if (!_disposed && _data != null)
            {
                CryptographicOperations.ZeroMemory(_data);
                _data = null;
                _disposed = true;
            }
        }

        /// <summary>
        /// Finalizer that ensures the key data is securely wiped from memory
        /// if the object was not explicitly disposed.
        /// </summary>
        ~SecretKey()
        {
            Dispose();
        }
    }
}
