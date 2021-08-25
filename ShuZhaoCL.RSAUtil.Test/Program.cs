using ShuZhaoCL.RSAUtil;
using System;

namespace ShuZhaoCL.RSAUtil.Test
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");
            var pkcs8Key = RSAKeyGenerator.Pkcs8Key();
            Console.WriteLine(pkcs8Key.PrivateKey);
            Console.WriteLine(pkcs8Key.PublicKey);
        }
    }
}
