using System.Security.Cryptography;

namespace KeyForge
{
    public class Secret : IDisposable
    {
        private byte[] _secret;
        private bool _disposed;

        public Secret(byte[] secret)
        {
            _secret = secret;
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
        public ReadOnlySpan<byte> GetBytes()
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _secret;
        }

        /// <summary>
        /// Securely releases all resources used by this instance.
        /// The key data is cleared from memory before disposal to prevent sensitive information leaks.
        /// </summary>
        public void Dispose()
        {
            if (!_disposed && _secret != null)
            {
                CryptographicOperations.ZeroMemory(_secret);
                _disposed = true;
            }
        }

        /// <summary>
        /// Finalizer that ensures the key data is securely wiped from memory
        /// if the object was not explicitly disposed.
        /// </summary>
        ~Secret()
        {
            Dispose();
        }
    }
}
