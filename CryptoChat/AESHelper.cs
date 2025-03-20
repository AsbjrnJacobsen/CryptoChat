using System.Security.Cryptography;
using System.Text;

namespace CryptoChat
{
    public class AESHelper
    {
        // Generate AES Key (32 bytes for AES-256)
        public static byte[] GenerateAESKey()
        {
            byte[] key = new byte[32];
            RandomNumberGenerator.Fill(key);
            return key;
        }

        // Encrypt message with AES-GCM
        public static (byte[] ciphertext, byte[] iv, byte[] tag) EncryptMessage(string message, byte[] aesKey)
        {
            using (AesGcm aes = new AesGcm(aesKey, 16)) // Tag size of 16 bytes
            {
                byte[] iv = new byte[12]; // Standard IV size for AES-GCM
                RandomNumberGenerator.Fill(iv);

                byte[] ciphertext = new byte[Encoding.UTF8.GetByteCount(message)];
                byte[] tag = new byte[16]; // Authentication tag

                aes.Encrypt(iv, Encoding.UTF8.GetBytes(message), ciphertext, tag);

                return (ciphertext, iv, tag);
            }
        }

        // Decrypt message with AES-GCM
        public static string DecryptMessage(byte[] ciphertext, byte[] aesKey, byte[] iv, byte[] tag)
        {
            using (AesGcm aes = new AesGcm(aesKey, 16))
            {
                byte[] decryptedMessage = new byte[ciphertext.Length];
                aes.Decrypt(iv, ciphertext, tag, decryptedMessage);
                return Encoding.UTF8.GetString(decryptedMessage);
            }
        }
    }
}