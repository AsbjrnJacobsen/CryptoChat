using System;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CryptoChat
{
    public class ChatClient
    {
        // File to locate the server's public key
        private const string ServerPublicKeyFile = "serverPublicKey.xml";

        private byte[] _sessionKey; // (Optional if using a session key, not used in this snippet)
        private RSAParameters _rsaPublic;
        private RSAParameters _rsaPrivate;

        public async Task StartAsync(string serverAddress, int port)
        {
            // Check if the server's public key file exists
            if (!File.Exists(ServerPublicKeyFile))
            {
                Console.WriteLine("Server public key file not found.");
                return;
            }

            // Read the server's public key from file and import it
            string publicKeyXml = File.ReadAllText(ServerPublicKeyFile);
            RSAParameters serverPublicKey = RSAHelper.ImportPublicKey(publicKeyXml);

            // Connect to the server
            TcpClient client = new TcpClient();
            await client.ConnectAsync(serverAddress, port);
            NetworkStream stream = client.GetStream();

            Console.WriteLine("Client connected.");

            // Generate RSA key pair for this client
            RSAHelper.GenerateRSAKeyPair(out _rsaPublic, out _rsaPrivate);
            string clientPublicKeyXml = RSAHelper.ExportPublicKey(_rsaPublic);
            byte[] clientPublicKeyBytes = Encoding.UTF8.GetBytes(clientPublicKeyXml);
            byte[] clientPublicKeyLength = BitConverter.GetBytes(clientPublicKeyBytes.Length);

            // Send client's public key (length-prefixed) to the server
            await stream.WriteAsync(clientPublicKeyLength, 0, clientPublicKeyLength.Length);
            await stream.WriteAsync(clientPublicKeyBytes, 0, clientPublicKeyBytes.Length);
            Console.WriteLine("Sent client's public RSA key to server.");

            // Receive the encrypted session key from the server
            byte[] lengthBytes = new byte[4];
            await stream.ReadAsync(lengthBytes, 0, 4);
            int encryptedKeyLength = BitConverter.ToInt32(lengthBytes, 0);
            byte[] encryptedSessionKey = new byte[encryptedKeyLength];
            await stream.ReadAsync(encryptedSessionKey, 0, encryptedSessionKey.Length);
            Console.WriteLine("Received encrypted session key from server.");

            // Decrypt the session key using the client's RSA private key
            byte[] sessionKey = RSAHelper.DecryptRSA(encryptedSessionKey, _rsaPrivate);
            Console.WriteLine("Decrypted session key.");

            // (Optional) You can store this session key if needed:
            _sessionKey = sessionKey;

            // Start a background listener for incoming messages
            _ = Task.Run(async () =>
            {
                byte[] buffer = new byte[1024];
                while (true)
                {
                    int byteCount = await stream.ReadAsync(buffer, 0, buffer.Length);
                    if (byteCount == 0) break;
                    // For this example, we expect a payload formatted as: ciphertext|iv|tag (Base64 encoded)
                    string incomingPayload = Encoding.UTF8.GetString(buffer, 0, byteCount);
                    var parts = incomingPayload.Split('|');
                    if (parts.Length == 3)
                    {
                        byte[] ciphertext = Convert.FromBase64String(parts[0]);
                        byte[] iv = Convert.FromBase64String(parts[1]);
                        byte[] tag = Convert.FromBase64String(parts[2]);
                        string decryptedMessage = AESHelper.DecryptMessage(ciphertext, sessionKey, iv, tag);
                        Console.WriteLine("Received message: " + decryptedMessage);
                    }
                    else
                    {
                        Console.WriteLine("Received invalid payload: " + incomingPayload);
                    }
                }
            });

            // Sending messages loop
            Console.WriteLine("You can now type messages to send:");
            while (true)
            {
                string message = Console.ReadLine();
                if (string.IsNullOrEmpty(message)) break;

                // Encrypt the message using AES with the session key
                var (ciphertext, iv, tag) = AESHelper.EncryptMessage(message, sessionKey);
                // Package the encrypted parts into a single payload (Base64 encoded with '|' as delimiter)
                string payload = Convert.ToBase64String(ciphertext) + "|" +
                                 Convert.ToBase64String(iv) + "|" +
                                 Convert.ToBase64String(tag);
                byte[] payloadBytes = Encoding.UTF8.GetBytes(payload);
                await stream.WriteAsync(payloadBytes, 0, payloadBytes.Length);
                Console.WriteLine("Sent encrypted message.");
            }

            client.Close();
        }
    }
}
