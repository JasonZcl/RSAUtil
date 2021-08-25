using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using ShuZhacoCL.RSAUtil.Entitys;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Xml.Linq;

namespace ShuZhacoCL.RSAUtil
{

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

            XElement privatElement = new XElement("RSAKeyValue");
            //Modulus
            XElement primodulus = new XElement("Modulus", Convert.ToBase64String(rsaKeyInfo.Modulus));
            //Exponent
            XElement priexponent = new XElement("Exponent", Convert.ToBase64String(rsaKeyInfo.Exponent));
            //P
            XElement prip = new XElement("P", Convert.ToBase64String(rsaKeyInfo.P));
            //Q
            XElement priq = new XElement("Q", Convert.ToBase64String(rsaKeyInfo.Q));
            //DP
            XElement pridp = new XElement("DP", Convert.ToBase64String(rsaKeyInfo.DP));
            //DQ
            XElement pridq = new XElement("DQ", Convert.ToBase64String(rsaKeyInfo.DQ));
            //InverseQ
            XElement priinverseQ = new XElement("InverseQ", Convert.ToBase64String(rsaKeyInfo.InverseQ));
            //D
            XElement prid = new XElement("D", Convert.ToBase64String(rsaKeyInfo.D));

            privatElement.Add(primodulus);
            privatElement.Add(priexponent);
            privatElement.Add(prip);
            privatElement.Add(priq);
            privatElement.Add(pridp);
            privatElement.Add(pridq);
            privatElement.Add(priinverseQ);
            privatElement.Add(prid);

            XElement publicElement = new XElement("RSAKeyValue");
            //Modulus
            XElement pubmodulus = new XElement("Modulus", Convert.ToBase64String(rsaKeyInfo.Modulus));
            //Exponent
            XElement pubexponent = new XElement("Exponent", Convert.ToBase64String(rsaKeyInfo.Exponent));

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
        /// <param name="format">Whether the format is true If it is standard pem file format(默认false)</param>
        /// <returns></returns>
        public static RSAKey Pkcs1Key(int keySize = 2048, bool format = false)
        {
            RSAKey rSAKey = new();

            IAsymmetricCipherKeyPairGenerator kpGen = GeneratorUtilities.GetKeyPairGenerator("RSA");
            kpGen.Init(new KeyGenerationParameters(new SecureRandom(), keySize));
            var keyPair = kpGen.GenerateKeyPair();

            StringWriter sw = new StringWriter();
            PemWriter pWrt = new PemWriter(sw);
            pWrt.WriteObject(keyPair.Private);
            pWrt.Writer.Close();
            var privateKey = sw.ToString();

            if (!format)
            {
                privateKey = privateKey.Replace("-----BEGIN RSA PRIVATE KEY-----", "").Replace("-----END RSA PRIVATE KEY-----", "").Replace(Environment.NewLine, "");
            }

            StringWriter swpub = new StringWriter();
            PemWriter pWrtpub = new PemWriter(swpub);
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
        /// <param name="format">Whether the format is true If it is standard pem file format(默认false)</param>
        /// <returns></returns>
        public static RSAKey Pkcs8Key(int keySize = 2014, bool format = false)
        {
            RSAKey rSAKey = new();

            IAsymmetricCipherKeyPairGenerator kpGen = GeneratorUtilities.GetKeyPairGenerator("RSA");
            kpGen.Init(new KeyGenerationParameters(new SecureRandom(), keySize));
            var keyPair = kpGen.GenerateKeyPair();

            StringWriter swpri = new StringWriter();
            PemWriter pWrtpri = new PemWriter(swpri);
            Pkcs8Generator pkcs8 = new Pkcs8Generator(keyPair.Private);
            pWrtpri.WriteObject(pkcs8);
            pWrtpri.Writer.Close();
            string privateKey = swpri.ToString();

            if (!format)
            {
                privateKey = privateKey.Replace("-----BEGIN PRIVATE KEY-----", "").Replace("-----END PRIVATE KEY-----", "").Replace(Environment.NewLine, "");
            }

            StringWriter swpub = new StringWriter();
            PemWriter pWrtpub = new PemWriter(swpub);
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
}
