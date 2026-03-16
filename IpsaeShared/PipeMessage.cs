using System.Text;

namespace IpsaeShared;

/// <summary>
/// Pipe message format: [Command(1)] [PayloadLength(4)] [Payload(N)]
/// </summary>
public class PipeMessage
{
    public PipeCommand Command { get; init; }
    public byte[] Payload { get; init; } = [];

    public static PipeMessage Status(ServiceStatusCode status)
    {
        return new PipeMessage
        {
            Command = PipeCommand.StatusResponse,
            Payload = [(byte)status]
        };
    }

    public static PipeMessage EngineCommand(EngineCommandCode command)
    {
        return new PipeMessage
        {
            Command = PipeCommand.EngineCommand,
            Payload = [(byte)command]
        };
    }

    public static PipeMessage FromCommand(PipeCommand command)
    {
        return new PipeMessage { Command = command };
    }

    public ServiceStatusCode GetStatusCode()
    {
        return Payload.Length > 0 ? (ServiceStatusCode)Payload[0] : ServiceStatusCode.Inactive;
    }

    public EngineCommandCode GetEngineCommandCode()
    {
        return Payload.Length > 0 ? (EngineCommandCode)Payload[0] : EngineCommandCode.None;
    }

    public byte[] ToBytes()
    {
        var length = BitConverter.GetBytes(Payload.Length);
        var result = new byte[1 + 4 + Payload.Length];
        result[0] = (byte)Command;
        Buffer.BlockCopy(length, 0, result, 1, 4);
        if (Payload.Length > 0)
            Buffer.BlockCopy(Payload, 0, result, 5, Payload.Length);
        return result;
    }

    public static async Task<PipeMessage?> ReadAsync(Stream stream, CancellationToken ct = default)
    {
        var header = new byte[5];
        var read = await ReadExactAsync(stream, header, 0, 5, ct);
        if (!read) return null;

        var command = (PipeCommand)header[0];
        var payloadLength = BitConverter.ToInt32(header, 1);

        if (payloadLength < 0 || payloadLength > 1024 * 64)
            return null;

        var payload = Array.Empty<byte>();
        if (payloadLength > 0)
        {
            payload = new byte[payloadLength];
            var payloadRead = await ReadExactAsync(stream, payload, 0, payloadLength, ct);
            if (!payloadRead) return null;
        }

        return new PipeMessage { Command = command, Payload = payload };
    }

    private static async Task<bool> ReadExactAsync(Stream stream, byte[] buffer, int offset, int count, CancellationToken ct)
    {
        var totalRead = 0;
        while (totalRead < count)
        {
            var bytesRead = await stream.ReadAsync(buffer.AsMemory(offset + totalRead, count - totalRead), ct);
            if (bytesRead == 0) return false;
            totalRead += bytesRead;
        }
        return true;
    }
}
