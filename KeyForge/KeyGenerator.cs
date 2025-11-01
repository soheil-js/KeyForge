namespace KeyForge
{
    public static class KeyGenerator
    {
        public static string Create(ReadOnlySpan<byte> secret)
        {
            char[] baseKey = Utils.GetRandomBaseKey();
            ulong checksum = Utils.CalculateSecureChecksum(baseKey, secret);
            return Utils.GenerateKey(baseKey, checksum);
        }

        public static bool Validate(string deviceKey, ReadOnlySpan<byte> secret)
        {
            return Utils.ValidateKey(deviceKey, secret);
        }
    }
}
