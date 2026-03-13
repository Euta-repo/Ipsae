using System.IO.Pipes;
using IpsaeShared;

namespace IpsaeService;

public class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;
    private ServiceStatusCode _status = ServiceStatusCode.Active;

    public Worker(ILogger<Worker> logger)
    {
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("IpsaeIDS Pipe Server starting");
        await Task.Yield();

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await using var server = new NamedPipeServerStream(
                    PipeProtocol.PipeName,
                    PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous);

                await server.WaitForConnectionAsync(stoppingToken);
                _logger.LogInformation("Client connected");

                await HandleClientAsync(server, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Pipe error");
            }
        }
    }

    private async Task HandleClientAsync(NamedPipeServerStream server, CancellationToken ct)
    {
        try
        {
            while (server.IsConnected && !ct.IsCancellationRequested)
            {
                var message = await PipeMessage.ReadAsync(server, ct);
                if (message == null) break;

                var response = HandleMessage(message);
                if (response != null)
                {
                    var bytes = response.ToBytes();
                    await server.WriteAsync(bytes, ct);
                    await server.FlushAsync(ct);
                }
            }
        }
        catch (IOException)
        {
            _logger.LogInformation("Client disconnected");
        }
    }

    private PipeMessage? HandleMessage(PipeMessage message)
    {
        switch (message.Command)
        {
            case PipeCommand.QueryStatus:
                return PipeMessage.Status(_status);

            case PipeCommand.StartService:
                _logger.LogInformation("Start command received");
                _status = ServiceStatusCode.Starting;
                // TODO: actual start logic, then set Active
                _status = ServiceStatusCode.Active;
                return PipeMessage.Status(_status);

            case PipeCommand.StopService:
                _logger.LogInformation("Stop command received");
                _status = ServiceStatusCode.Stopping;
                // TODO: actual stop logic, then set Inactive
                _status = ServiceStatusCode.Inactive;
                return PipeMessage.Status(_status);

            default:
                return null;
        }
    }
}
