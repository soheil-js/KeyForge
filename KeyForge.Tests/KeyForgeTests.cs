using System.Security.Cryptography;
using System.Text;

namespace KeyForge.Tests
{
    public class KeyForgeTests
    {
        private readonly SecretKey secretKey = SecretKey.CreateRandom();

        [Fact]
        public void Create_ShouldReturnNonEmptyKey()
        {
            string key = KeyGenerator.Create(secretKey.AsSpan());
            Assert.False(string.IsNullOrWhiteSpace(key));
            Assert.Equal(4, key.Split('-').Length);
        }

        [Fact]
        public void Validate_ShouldReturnTrueForGeneratedKey()
        {
            string key = KeyGenerator.Create(secretKey.AsSpan());
            bool result = KeyGenerator.Validate(key, secretKey.AsSpan());
            Assert.True(result);
        }

        [Fact]
        public void Validate_ShouldReturnFalseForModifiedKey()
        {
            string key = KeyGenerator.Create(secretKey.AsSpan());

            char[] chars = key.ToCharArray();
            chars[chars.Length - 1] = chars[chars.Length - 1] != 'A' ? 'A' : 'B';
            string modifiedKey = new string(chars);

            bool result = KeyGenerator.Validate(modifiedKey, secretKey.AsSpan());
            Assert.False(result);
        }

        [Fact]
        public void Validate_ShouldReturnFalseForWrongSecret()
        {
            string key = KeyGenerator.Create(secretKey.AsSpan());

            byte[] wrongSecret = new byte[32];
            RandomNumberGenerator.Fill(wrongSecret);
            bool result = KeyGenerator.Validate(key, wrongSecret);
            Assert.False(result);
        }

        [Fact]
        public void Validate_ShouldReturnFalseForMalformedKey()
        {
            string malformedKey = "1234-5678-ABCD";
            bool result = KeyGenerator.Validate(malformedKey, secretKey.AsSpan());
            Assert.False(result);

            string emptyKey = "";
            Assert.False(KeyGenerator.Validate(emptyKey, secretKey.AsSpan()));
        }

        [Fact]
        public void KeyGenerator_ShouldThrowForShortSecret()
        {
            byte[] shortSecret = new byte[8];
            RandomNumberGenerator.Fill(shortSecret);

            Assert.Throws<ArgumentException>(() =>
            {
                _ = KeyGenerator.Create(shortSecret);
            });
        }
    }
}