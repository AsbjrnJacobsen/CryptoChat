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
        private byte[] _sessionKey; // for group AES 
        private ECDiffieHellman _ecdh;
        private byte[] _clientECDHPublicKey;
        
        
        public async Task StartAsync(string serverAddress, int port)
        {
            
            // 1. Connect to the server + create client ECDH key pair
            TcpClient client = new TcpClient();
            await client.ConnectAsync(serverAddress, port);
            NetworkStream stream = client.GetStream();
            Console.WriteLine("Client connected.");

            _ecdh = ECDHHelper.CreateECDH(out var clientPublicKey);
            if (clientPublicKey == null)
            {
                Console.WriteLine("Failed to generate ECDH public key.");
                return;
            }
            _clientECDHPublicKey = clientPublicKey;
            
            // 2. Send clients ECDH public key to the server
            byte[] clientPublicKeyLength = BitConverter.GetBytes(_clientECDHPublicKey.Length);
            await stream.WriteAsync(clientPublicKeyLength, 0, clientPublicKeyLength.Length);
            await stream.WriteAsync(_clientECDHPublicKey, 0, _clientECDHPublicKey.Length);
            Console.WriteLine("Sent clients ECDH public key to server.");
            
            // 3. Receive servers ECDH public key.
            byte[] lengthBytes = new byte[4];
            await ReadExactAsync(stream, lengthBytes, 0, 4);
            int serverPublicKeyLength = BitConverter.ToInt32(lengthBytes, 0);
            byte[] serverECDHPublicKey = new byte[serverPublicKeyLength];
            await ReadExactAsync(stream, serverECDHPublicKey, 0, serverPublicKeyLength);
            Console.WriteLine("Received server ECDH public key from server.");

            // 4. Derive shared key using clients ECDH instance and servers public key.
            byte[] sharedKey = ECDHHelper.DeriveSharedKey(_ecdh, serverECDHPublicKey);
            Console.WriteLine("Derived shared key using ECDH");
            
            // 5. Receive the encrypted group AES session key from the server.
            await ReadExactAsync(stream, lengthBytes, 0, 4);
            int payloadLength = BitConverter.ToInt32(lengthBytes, 0);
            byte[] encryptedSessionKeyPayloadBytes = new byte[payloadLength];
            await ReadExactAsync(stream, encryptedSessionKeyPayloadBytes, 0, payloadLength);
            string encryptedSessionKeyPayload = Encoding.UTF8.GetString(encryptedSessionKeyPayloadBytes);
            Console.WriteLine("Received encrypted group session key from server.");
            
            // The payload is formatted as Base64(Cipthertext)|Base64(iv)|Base64(tag)
            string[] parts = encryptedSessionKeyPayload.Split('|');
            if (parts.Length != 3)
            {
                Console.WriteLine("Invalid encrypted session key payload format.");
                return;
            }
            byte[] ciphertext = Convert.FromBase64String(parts[0]);
            byte[] iv = Convert.FromBase64String(parts[1]);
            byte[] tag = Convert.FromBase64String(parts[2]);
            
            // Decrypt session key using the shared key.
            // The Decrypted string is a base64-encoded AES key.
            string sessionKeyBase64 = AESHelper.DecryptMessage(ciphertext, sharedKey, iv, tag);
            _sessionKey = Convert.FromBase64String(sessionKeyBase64);
            Console.WriteLine("Decrypted group AES session key.");

            // Start a background listener for incoming messages
            _ = Task.Run(async () =>
            {
                byte[] buffer = new byte[1024];
                while (true)
                {
                    int byteCount = await stream.ReadAsync(buffer, 0, buffer.Length);
                    if (byteCount == 0) break;
                    
                    // Handling incoming payload - split in 3 parts
                    string incomingPayload = Encoding.UTF8.GetString(buffer, 0, byteCount);
                    var messageParts = incomingPayload.Split('|');
                    if (messageParts.Length == 3)
                    {
                        byte[] messageCiphertext = Convert.FromBase64String(messageParts[0]);
                        byte[] messageIV = Convert.FromBase64String(messageParts[1]);
                        byte[] messageTag = Convert.FromBase64String(messageParts[2]);
                        string decryptedMessage = AESHelper.DecryptMessage(messageCiphertext, _sessionKey, messageIV, messageTag);
                        Console.WriteLine("Received msg: " + decryptedMessage);
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

                // Encrypt the message using the group AES session key
                var (messageCiphertext, messageIV, messageTag) = AESHelper.EncryptMessage(message, _sessionKey);
                
                // Package the encrypted parts into a single payload (Base64 encoded with '|' as delimiter)
                string payload = Convert.ToBase64String(messageCiphertext) + "|" +
                                 Convert.ToBase64String(messageIV) + "|" +
                                 Convert.ToBase64String(messageTag);
                byte[] payloadBytes = Encoding.UTF8.GetBytes(payload);
                await stream.WriteAsync(payloadBytes, 0, payloadBytes.Length);
                Console.WriteLine("Sent encrypted message.");
            }

            client.Close();
        }
    private async Task ReadExactAsync(NetworkStream stream, byte[] buffer, int offset, int count)
    {
        int totalRead = 0;
        while (totalRead < count)
        {
            int bytesRead = await stream.ReadAsync(buffer, offset + totalRead, count - totalRead);
            if (bytesRead == 0)
            {
                throw new IOException("Unexpected end of stream.");
            }
            totalRead += bytesRead;
        }
    }

    }
}
