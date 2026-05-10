using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KeyForge
{
    public static class Extensions
    {
        internal static int TrimToUpperInvariant(this ReadOnlySpan<char> input, Span<char> output)
        {
            int start = 0;
            while (start < input.Length && char.IsWhiteSpace(input[start]))
                start++;

            if (start == input.Length)
                return 0;

            int end = input.Length - 1;
            while (end >= start && char.IsWhiteSpace(input[end]))
                end--;

            int length = end - start + 1;
            int outputIndex = 0;

            if (output.Length < length)
                throw new ArgumentException("Output buffer is too small.");

            for (int i = 0; i < length; i++)
                output[outputIndex++] = char.ToUpperInvariant(input[start + i]);

            return length;
        }

        public static KeyGenerator GetKeyGenerator(this Secret secret)
        {
            return new KeyGenerator(secret);
        }

        public static string GenerateKey(this Secret secret)
        {
            return new KeyGenerator(secret).GenerateKey();
        }

        public static bool ValidateKey(this Secret secret, string key)
        {
            return new KeyGenerator(secret).ValidateKey(key);
        }

        public static bool ValidateKey(this string key, Secret secret)
        {
            return new KeyGenerator(secret).ValidateKey(key);
        }
    }
}
