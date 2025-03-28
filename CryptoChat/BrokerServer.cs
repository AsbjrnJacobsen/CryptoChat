using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CryptoChat;

public class BrokerServer
{
    private TcpListener _listener;
    private ConcurrentBag<TcpClient> _clients = new ConcurrentBag<TcpClient>();
    private byte[] _sessionKey;
    private const string ServerPublicKeyFile = "serverPublicKey.xml";

    public async Task StartAsync(int port)
    {
        //Generate AES sesseion key on startup
        _sessionKey = AESHelper.GenerateAESKey();
        Console.WriteLine("Session AES Key generated.");
        
        
        _listener = new TcpListener(IPAddress.Any, port);
        _listener.Start();
        Console.WriteLine("Broker server listening on port: " + port);

        while (true)
        {
            var client = await _listener.AcceptTcpClientAsync();
            _ = HandleClientAsync(client);
        }
    }

    private async Task HandleClientAsync(TcpClient client)
    {
        
        try
        {
            // Limit Chats to 2 Users/Clients
            if (_clients.Count >= 2)
            {
                Console.WriteLine("Rejected connection. Chat is limited to 2 users.");
                client.Close();
                return;
            }
            
            var stream = client.GetStream();
            
            // 1. Get Clients ECDH public key - length fixed
            byte[] lengthBytes = new byte[4];
            await ReadExactAsync(stream, lengthBytes, 0, 4);
            int clientPublicKeyLength = BitConverter.ToInt32(lengthBytes, 0);
            byte[] clientECDHPublicKey = new byte[clientPublicKeyLength];
            await ReadExactAsync(stream, clientECDHPublicKey, 0, clientPublicKeyLength);
            Console.WriteLine("Received client ECDH public key.");
            
            // 2. Generate server's ECDH key pair + get public key
            using var serverECDH = ECDHHelper.CreateECDH(out byte[] serverECDHPublicKey);
            
            // 3. Send Servers ECDH public key to client
            byte[] serverPublicKeyLength = BitConverter.GetBytes(serverECDHPublicKey.Length);
            await stream.WriteAsync(serverPublicKeyLength, 0, serverPublicKeyLength.Length);
            await stream.WriteAsync(serverECDHPublicKey, 0, serverECDHPublicKey.Length);

            Console.WriteLine("Sent server's ECDH public key to  client.");
            
            // 4. Derive shared key using ECDH
            byte[] sharedKey = ECDHHelper.DeriveSharedKey(serverECDH, clientECDHPublicKey);
            Console.WriteLine("Derived shared key using ECDH.");
            
            // 5. Encrypt group AES session key using the shared key.
            // Converting AES key to Base64 string to encrypt it.
            string sessionKeyBase64 = Convert.ToBase64String(_sessionKey);
            var (ciphertext, iv, tag) = AESHelper.EncryptMessage(sessionKeyBase64, sharedKey);
            string encryptedSessionKeyPayload = Convert.ToBase64String(ciphertext) + "|" +
                                                Convert.ToBase64String(iv) + "|" +
                                                Convert.ToBase64String(tag);
            byte[] encryptedSessionKeyPayloadBytes = Encoding.UTF8.GetBytes(encryptedSessionKeyPayload);
            byte[] payloadLengthBytes = BitConverter.GetBytes(encryptedSessionKeyPayloadBytes.Length);
            await stream.WriteAsync( payloadLengthBytes, 0, 4);
            await stream.WriteAsync( encryptedSessionKeyPayloadBytes, 0, encryptedSessionKeyPayloadBytes.Length);
            Console.WriteLine("Sent encrypted group session key to client.");
            
            _clients.Add(client);

            
            // 6. Listen for encrypted messages from the client.
            byte[] buffer = new byte[1024];
            while (true)
            {
                int byteCount = await stream.ReadAsync(buffer, 0, buffer.Length);
                if (byteCount == 0)
                    break; // Client DC.
                
                string payload = Encoding.UTF8.GetString(buffer, 0, byteCount);
                Console.WriteLine("Broker received encrypted message payload.");
                
                // OBS - Relay the message to all other clients.
                await PublishMessage(payload, client);
            }
        }
        catch (Exception e)
        {
            Console.WriteLine("Error handling client: " + e.Message);
        }
        finally{client.Close();}
    }

    private async Task PublishMessage(string message, TcpClient sender)
    {
        byte[] data = Encoding.UTF8.GetBytes(message);
        
        foreach (var client in _clients)
        {
            if (client == sender)
                continue;

            try
            {
                // Check if client is connected
                if (!client.Connected)
                {
                    Console.WriteLine("Skipping a disconnected client.");
                    client.Close();
                    continue;
                }
                
                await client.GetStream().WriteAsync(data, 0, data.Length);
            }
            catch (ObjectDisposedException)
            {
                Console.WriteLine("Skipping a disposed client.");
                throw;
            }
            catch (Exception e)
            {
                Console.WriteLine("Error publishing message: " + e.Message);
            }
        }
        
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

    
    // End
}