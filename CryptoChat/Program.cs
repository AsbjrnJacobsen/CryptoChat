using System;
using System.Threading.Tasks;

namespace CryptoChat
{
    internal class Program
    {
        static async Task Main(string[] args)
        {
            Console.WriteLine("Press 1 for starting the broker server, 2 for a client.");
            string choice = Console.ReadLine();
            if (choice == "1")
            {
                BrokerServer server = new BrokerServer();
                await server.StartAsync(12345);
            }
            else if (choice == "2")
            {
                ChatClient client = new ChatClient();
                await client.StartAsync("127.0.0.1", 12345);
            }
        }
    }
}