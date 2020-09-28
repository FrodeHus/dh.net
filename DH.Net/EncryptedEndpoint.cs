using System;
using System.Globalization;
using System.IO;
using System.Numerics;
using System.Text;

namespace DH.Net.Crypto
{
    public class EncryptedEndpoint
    {
        private readonly KeyInfo keyInfo;
        private int basePublicKey;
        private int moduloPublicKey;
        private int partialKey;
        private EncryptedEndpoint remoteEndpoint;

        public EncryptedEndpoint(KeyInfo keyInfo)
        {
            this.keyInfo = keyInfo;
        }

        public void Connect(EncryptedEndpoint remote)
        {
            basePublicKey = keyInfo.PublicKey;
            moduloPublicKey = remote.ExchangePublicKeys(basePublicKey);
            partialKey = remote.ExchangePartialKeys(GeneratePartialKey());
            if (moduloPublicKey == 0)
                throw new InvalidOperationException("Failed to retrieve public key");
            remoteEndpoint = remote;
        }

        public int ExchangePartialKeys(int partialKey)
        {
            this.partialKey = partialKey;
            return GeneratePartialKey();
        }

        public int ExchangePublicKeys(int publicKey)
        {
            basePublicKey = publicKey;
            moduloPublicKey = keyInfo.PublicKey;
            return moduloPublicKey;
        }

        public int GeneratePartialKey()
        {
            var key = BigInteger.Pow(basePublicKey, keyInfo.PrivateKey) % moduloPublicKey;
            return (int)key;
        }

        public void Send(string message)
        {
            var encrypted = Encrypt(message);
            Console.WriteLine($"==> {encrypted}");
            remoteEndpoint.Receive(encrypted);
        }

        public void Receive(string encryptedMessage)
        {
            var message = Decrypt(encryptedMessage);
            Console.WriteLine($"<== {message}");
        }

        private string Encrypt(string message)
        {
            var builder = new StringBuilder();
            var key = GenerateFullKey();
            foreach (var c in message)
            {
                builder.Append((char)(c + key));
            }
            return builder.ToString();
        }

        private string Decrypt(string encryptedMessage)
        {
            var builder = new StringBuilder();
            var key = GenerateFullKey();
            foreach (var c in encryptedMessage)
            {
                builder.Append((char)(c - key));
            }
            return builder.ToString();
        }

        private int GenerateFullKey()
        {
            var key = BigInteger.Pow(partialKey, keyInfo.PrivateKey) % moduloPublicKey;
            return (int)key;
        }
    }
}