global using Org.BouncyCastle.Crypto;
global using Org.BouncyCastle.OpenSsl;
global using Org.BouncyCastle.Security;
global using System;
global using System.IO;
global using System.Security.Cryptography;
global using System.Xml.Linq;
using ShuZhaoCL.RSAUtil.Entitys;

namespace ShuZhaoCL.RSAUtil;

/// <summary>
///  Rsa Key Generator
/// Author:ShuZhaoCL
/// </summary>
public class RSAKeyGenerator
{
    /// <summary>
    /// Generate XML Format RSA Key
    /// </summary>
    /// <param name="keySize">Key Size.Unit: bits(默认2048)</param>
    /// <returns></returns>
    public static RSAKey XmlKey(int keySize = 2048)
    {
        RSA rsa = RSA.Create();
        rsa.KeySize = keySize;
        RSAParameters rsaKeyInfo = rsa.ExportParameters(true);
        RSAKey rSAKey = new();

        XElement privatElement = new("RSAKeyValue");
        //Modulus
        XElement primodulus = new("Modulus", Convert.ToBase64String(rsaKeyInfo.Modulus));
        //Exponent
        XElement priexponent = new("Exponent", Convert.ToBase64String(rsaKeyInfo.Exponent));
        //P
        XElement prip = new("P", Convert.ToBase64String(rsaKeyInfo.P));
        //Q
        XElement priq = new("Q", Convert.ToBase64String(rsaKeyInfo.Q));
        //DP
        XElement pridp = new("DP", Convert.ToBase64String(rsaKeyInfo.DP));
        //DQ
        XElement pridq = new("DQ", Convert.ToBase64String(rsaKeyInfo.DQ));
        //InverseQ
        XElement priinverseQ = new("InverseQ", Convert.ToBase64String(rsaKeyInfo.InverseQ));
        //D
        XElement prid = new("D", Convert.ToBase64String(rsaKeyInfo.D));

        privatElement.Add(primodulus);
        privatElement.Add(priexponent);
        privatElement.Add(prip);
        privatElement.Add(priq);
        privatElement.Add(pridp);
        privatElement.Add(pridq);
        privatElement.Add(priinverseQ);
        privatElement.Add(prid);

        XElement publicElement = new("RSAKeyValue");
        //Modulus
        XElement pubmodulus = new("Modulus", Convert.ToBase64String(rsaKeyInfo.Modulus));
        //Exponent
        XElement pubexponent = new("Exponent", Convert.ToBase64String(rsaKeyInfo.Exponent));

        publicElement.Add(pubmodulus);
        publicElement.Add(pubexponent);

        //添加公钥
        rSAKey.PublicKey = publicElement.ToString();
        //添加私钥
        rSAKey.PrivateKey = privatElement.ToString();

        return rSAKey;
    }

    /// <summary>
    /// Generate RSA key in Pkcs1 format
    /// </summary>
    /// <param name="keySize">Key Size.Unit: bits(默认2048)</param>
    /// <param name="format">Whether the format is true If it is standard pem file format(默认true)</param>
    /// <returns></returns>
    public static RSAKey Pkcs1Key(int keySize = 2048, bool format = true)
    {
        RSAKey rSAKey = new();

        IAsymmetricCipherKeyPairGenerator kpGen = GeneratorUtilities.GetKeyPairGenerator("RSA");
        kpGen.Init(new(new(), keySize));
        var keyPair = kpGen.GenerateKeyPair();

        StringWriter sw = new();
        PemWriter pWrt = new(sw);
        pWrt.WriteObject(keyPair.Private);
        pWrt.Writer.Close();
        var privateKey = sw.ToString();

        if (!format)
        {
            privateKey = privateKey.Replace("-----BEGIN RSA PRIVATE KEY-----", "").Replace("-----END RSA PRIVATE KEY-----", "").Replace(Environment.NewLine, "");
        }

        StringWriter swpub = new();
        PemWriter pWrtpub = new(swpub);
        pWrtpub.WriteObject(keyPair.Public);
        pWrtpub.Writer.Close();
        string publicKey = swpub.ToString();
        if (!format)
        {
            publicKey = publicKey.Replace("-----BEGIN PUBLIC KEY-----", "").Replace("-----END PUBLIC KEY-----", "").Replace(Environment.NewLine, "");
        }

        rSAKey.PrivateKey = privateKey;
        rSAKey.PublicKey = publicKey;

        return rSAKey;
    }

    /// <summary>
    /// Generate Pkcs8 format RSA key
    /// </summary>
    /// <param name="keySize">Key Size.Unit: bits(默认2048)</param>
    /// <param name="format">Whether the format is true If it is standard pem file format(默认true)</param>
    /// <returns></returns>
    public static RSAKey Pkcs8Key(int keySize = 2048, bool format = true)
    {
        RSAKey rSAKey = new();

        IAsymmetricCipherKeyPairGenerator kpGen = GeneratorUtilities.GetKeyPairGenerator("RSA");
        kpGen.Init(new(new(), keySize));
        var keyPair = kpGen.GenerateKeyPair();

        StringWriter swpri = new();
        PemWriter pWrtpri = new(swpri);
        Pkcs8Generator pkcs8 = new(keyPair.Private);
        pWrtpri.WriteObject(pkcs8);
        pWrtpri.Writer.Close();
        string privateKey = swpri.ToString();

        if (!format)
        {
            privateKey = privateKey.Replace("-----BEGIN PRIVATE KEY-----", "").Replace("-----END PRIVATE KEY-----", "").Replace(Environment.NewLine, "");
        }

        StringWriter swpub = new();
        PemWriter pWrtpub = new(swpub);
        pWrtpub.WriteObject(keyPair.Public);
        pWrtpub.Writer.Close();
        string publicKey = swpub.ToString();
        if (!format)
        {
            publicKey = publicKey.Replace("-----BEGIN PUBLIC KEY-----", "").Replace("-----END PUBLIC KEY-----", "").Replace(Environment.NewLine, "");
        }

        rSAKey.PrivateKey = privateKey;
        rSAKey.PublicKey = publicKey;

        return rSAKey;
    }
}
