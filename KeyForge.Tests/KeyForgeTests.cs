using System.Security.Cryptography;
using System.Text;

namespace KeyForge.Tests
{
    public class KeyForgeTests
    {
        private readonly byte[] secretBytes = new byte[32];

        public KeyForgeTests()
        {
            RandomNumberGenerator.Fill(secretBytes);
        }

        [Fact]
        public void Create_ShouldReturnNonEmptyKey()
        {
            string key = KeyGenerator.Create(secretBytes);
            Assert.False(string.IsNullOrWhiteSpace(key));
            Assert.Equal(4, key.Split('-').Length);
        }

        [Fact]
        public void Validate_ShouldReturnTrueForGeneratedKey()
        {
            string key = KeyGenerator.Create(secretBytes);
            bool result = KeyGenerator.Validate(key, secretBytes);
            Assert.True(result);
        }

        [Fact]
        public void Validate_ShouldReturnFalseForModifiedKey()
        {
            string key = KeyGenerator.Create(secretBytes);

            char[] chars = key.ToCharArray();
            chars[chars.Length - 1] = chars[chars.Length - 1] != 'A' ? 'A' : 'B';
            string modifiedKey = new string(chars);

            bool result = KeyGenerator.Validate(modifiedKey, secretBytes);
            Assert.False(result);
        }

        [Fact]
        public void Validate_ShouldReturnFalseForWrongSecret()
        {
            string key = KeyGenerator.Create(secretBytes);

            byte[] wrongSecret = new byte[32];
            RandomNumberGenerator.Fill(wrongSecret);
            bool result = KeyGenerator.Validate(key, wrongSecret);
            Assert.False(result);
        }

        [Fact]
        public void Validate_ShouldReturnFalseForMalformedKey()
        {
            string malformedKey = "1234-5678-ABCD";
            bool result = KeyGenerator.Validate(malformedKey, secretBytes);
            Assert.False(result);

            string emptyKey = "";
            Assert.False(KeyGenerator.Validate(emptyKey, secretBytes));
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