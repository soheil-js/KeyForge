using System.Security.Cryptography;
using System.Text;

namespace KeyForge.Tests
{
    public class KeyForgeTests
    {
        private readonly KeyGenerator _keyGenerator = new KeyGenerator(SecretFactory.CreateRandom());

        [Fact]
        public void Create_ShouldReturnNonEmptyKey()
        {
            string key = _keyGenerator.GenerateKey();
            Assert.False(string.IsNullOrWhiteSpace(key));
            Assert.Equal(4, key.Split('-').Length);
        }

        [Fact]
        public void Validate_ShouldReturnTrueForGeneratedKey()
        {
            string key = _keyGenerator.GenerateKey();
            bool result = _keyGenerator.ValidateKey(key);
            Assert.True(result);
        }

        [Fact]
        public void Validate_ShouldReturnFalseForModifiedKey()
        {
            string key = _keyGenerator.GenerateKey();

            char[] chars = key.ToCharArray();
            chars[chars.Length - 1] = chars[chars.Length - 1] != 'A' ? 'A' : 'B';
            string modifiedKey = new string(chars);

            bool result = _keyGenerator.ValidateKey(modifiedKey);
            Assert.False(result);
        }

        [Fact]
        public void Validate_ShouldReturnFalseForWrongSecret()
        {
            string key = _keyGenerator.GenerateKey();

            byte[] wrongSecret = new byte[32];
            RandomNumberGenerator.Fill(wrongSecret);
            bool result = _keyGenerator.ValidateKey(key);
            Assert.False(result);
        }

        [Fact]
        public void Validate_ShouldReturnFalseForMalformedKey()
        {
            string malformedKey = "1234-5678-ABCD";
            bool result = _keyGenerator.ValidateKey(malformedKey);
            Assert.False(result);

            string emptyKey = "";
            Assert.False(_keyGenerator.ValidateKey(emptyKey));
        }

        [Fact]
        public void _keyGenerator_ShouldThrowForShortSecret()
        {
            byte[] shortSecret = new byte[8];
            RandomNumberGenerator.Fill(shortSecret);

            Assert.Throws<ArgumentException>(() =>
            {
                _ = new KeyGenerator(SecretFactory.FromBytes(shortSecret)).GenerateKey();
            });
        }
    }
}