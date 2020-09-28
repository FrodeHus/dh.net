using System;
using System.Security.Cryptography;
namespace DH.Net.Crypto
{
    public class KeyInfo
    {
        private static RNGCryptoServiceProvider Provider { get; } = new RNGCryptoServiceProvider();
        public static KeyInfo Generate()
        {
            var publicKey = GetSecureRandomNumber();
            var privateKey = GetSecureRandomNumber();
            return new KeyInfo(publicKey, privateKey);
        }

        public KeyInfo(int publicKey, int privateKey)
        {
            PublicKey = publicKey;
            PrivateKey = privateKey;
        }

        public int PublicKey { get; }
        public int PrivateKey { get; }

        private static int GetSecureRandomNumber()
        {
            var bytes = new byte[2];
            Provider.GetBytes(bytes);
            var number = BitConverter.ToUInt16(bytes, 0);
            return number;
        }

    }
}