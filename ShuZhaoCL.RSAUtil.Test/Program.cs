using ShuZhaoCL.RSAUtil;
using System;

namespace ShuZhaoCL.RSAUtil.Test;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("pkcs8Key");
        var pkcs8Key = RSAKeyGenerator.Pkcs8Key();
        Console.WriteLine(pkcs8Key.PrivateKey);
        Console.WriteLine(pkcs8Key.PublicKey);

        Console.WriteLine("public key pkcs7=>xml:");
        //Console.WriteLine(RSAKeyGenerator.)
    }
}
