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
        
        // Generate the servers RSA key pair and export its public key
        RSAParameters serverPublicKey, serverPrivateKey;
        RSAHelper.GenerateRSAKeyPair(out serverPublicKey, out serverPrivateKey);
        string publicKeyXml = RSAHelper.ExportPublicKey(serverPublicKey);
        File.WriteAllText(ServerPublicKeyFile, publicKeyXml);
        Console.WriteLine("Server public key written to file.");
        
        _listener = new TcpListener(IPAddress.Any, port);
        _listener.Start();
        Console.WriteLine("Broker server listening on port: " + port);

        while (true)
        {
            var client = await _listener.AcceptTcpClientAsync();
            _clients.Add(client);
            _ = HandleClientAsync(client);
        }
    }

    private async Task HandleClientAsync(TcpClient client)
    {
        try
        {
            var stream = client.GetStream();
            
            // 1. Get Clients Public RSA Key
            byte[] lengthBytes = new byte[4];
            await stream.ReadAsync(lengthBytes, 0, 4);
            int publicKeyLength = BitConverter.ToInt32(lengthBytes, 0);
            
            byte[] publicKeyBytes = new byte[publicKeyLength];
            await stream.ReadAsync(publicKeyBytes, 0, publicKeyLength);
            string clientPublicKeyXml = Encoding.UTF8.GetString(publicKeyBytes);
            RSAParameters clientPublicKey = RSAHelper.ImportPublicKey(clientPublicKeyXml);
            Console.WriteLine("Received clients public RSA key.");
            
            // 2. Send AES session key, encrypted, to the client.
            byte[] encryptedSessionKey = RSAHelper.EncryptRSA(_sessionKey, clientPublicKey);
            byte[] encryptedKeyLength = BitConverter.GetBytes(encryptedSessionKey.Length);
            await stream.WriteAsync(encryptedKeyLength, 0, 4);
            await stream.WriteAsync(encryptedSessionKey, 0, encryptedSessionKey.Length);
            Console.WriteLine("Sent encrypted session key to the client.");
            
            // 3. Listen for encrypted messages from the client.
            byte[] buffer = new byte[1024];
            while (true)
            {
                int byteCount = await stream.ReadAsync(buffer, 0, buffer.Length);
                if (byteCount == 0)
                    break;
                // Client DC.
                
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
    
    // End
}