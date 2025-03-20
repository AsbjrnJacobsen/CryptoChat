using System;
using System.Security.Cryptography;

namespace CryptoChat
{
    public class RSAHelper
    {
        // Generate RSA Key Pair (Public and Private)
        public static RSAParameters GenerateRSAKeyPair(out RSAParameters publicKey, out RSAParameters privateKey)
        {
            using (RSA rsa = RSA.Create(2048))
            {
                publicKey = rsa.ExportParameters(false);
                privateKey = rsa.ExportParameters(true);
                return publicKey;
            }
        }

        // Export RSA public key as an XML string
        public static string ExportPublicKey(RSAParameters publicKey)
        {
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportParameters(publicKey);
                return rsa.ToXmlString(false); // false: export public key only
            }
        }

        // Import RSA public key from an XML string
        public static RSAParameters ImportPublicKey(string xml)
        {
            using (RSA rsa = RSA.Create())
            {
                rsa.FromXmlString(xml);
                return rsa.ExportParameters(false);
            }
        }

        // Encrypt data with RSA public key
        public static byte[] EncryptRSA(byte[] data, RSAParameters publicKey)
        {
            using (RSA rsa = RSA.Create(2048))
            {
                rsa.ImportParameters(publicKey);
                try
                {
                    return rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("RSA Encryption failed: " + ex.Message);
                    throw;
                }
            }
        }

        // Decrypt data with RSA private key
        public static byte[] DecryptRSA(byte[] data, RSAParameters privateKey)
        {
            using (RSA rsa = RSA.Create(2048))
            {
                rsa.ImportParameters(privateKey);
                try
                {
                    return rsa.Decrypt(data, RSAEncryptionPadding.OaepSHA256);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("RSA Decryption failed: " + ex.Message);
                    throw;
                }
            }
        }
    }
}
