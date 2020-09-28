using System;
using DH.Net.Crypto;

namespace DH.Net
{
    class Program
    {
        static void Main(string[] args)
        {
            var localKeys = KeyInfo.Generate();
            var remoteKeys = KeyInfo.Generate();

            var local = new EncryptedEndpoint(localKeys);
            var remote = new EncryptedEndpoint(remoteKeys);

            local.Connect(remote);

            local.Send("This is a test");

            Console.ReadLine();
        }
    }
}
