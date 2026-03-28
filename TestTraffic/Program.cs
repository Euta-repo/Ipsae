using System.Net;
using System.Net.Sockets;

Console.WriteLine("=== Ipsae Traffic Test Tool ===");
Console.WriteLine("주기적으로 외부 TCP/UDP 연결을 생성합니다.");
Console.WriteLine("종료: Ctrl+C");
Console.WriteLine();

var tcpTargets = new (string Host, int Port)[]
{
    ("93.184.216.34", 80),   // example.com
    ("142.250.207.14", 443), // google.com
    ("104.16.132.229", 80),  // cloudflare.com
    ("20.200.245.247", 443), // microsoft.com
    ("165.22.170.131", 80)
};

var udpTargets = new (string Host, int Port)[]
{
    ("8.8.8.8", 53),         // Google DNS
    ("1.1.1.1", 53),         // Cloudflare DNS
};

// 간단한 DNS 쿼리 패킷 (example.com A 레코드)
byte[] dnsQuery =
{
    0xAA, 0xBB,             // Transaction ID
    0x01, 0x00,             // Flags: Standard query
    0x00, 0x01,             // Questions: 1
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Answer/Authority/Additional: 0
    0x07, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e',
    0x03, (byte)'c', (byte)'o', (byte)'m',
    0x00,                   // Root
    0x00, 0x01,             // Type: A
    0x00, 0x01,             // Class: IN
};

int count = 0;

while (true)
{
    // TCP 연결 테스트
    foreach (var (host, port) in tcpTargets)
    {
        try
        {
            using var client = new TcpClient();
            var result = client.BeginConnect(host, port, null, null);
            bool connected = result.AsyncWaitHandle.WaitOne(2000);
            if (!connected)
            {
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] TCP Timeout: {host}:{port}");
                continue;
            }
            client.EndConnect(result);
            count++;
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] #{count} TCP Connected: {host}:{port}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] TCP Failed: {host}:{port} - {ex.Message}");
        }
    }

    // UDP DNS 쿼리 테스트
    foreach (var (host, port) in udpTargets)
    {
        try
        {
            using var udp = new UdpClient();
            udp.Client.ReceiveTimeout = 2000;
            var endpoint = new IPEndPoint(IPAddress.Parse(host), port);

            udp.Send(dnsQuery, dnsQuery.Length, endpoint);
            count++;
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] #{count} UDP Sent: {host}:{port}");

            var remoteEp = new IPEndPoint(IPAddress.Any, 0);
            byte[] response = udp.Receive(ref remoteEp);
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}]     UDP Recv: {response.Length} bytes from {remoteEp}");
        }
        catch (SocketException ex)
        {
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] UDP Failed: {host}:{port} - {ex.Message}");
        }
    }

    Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] --- Batch done. Waiting 2s ---");
    Thread.Sleep(2000);
}
