using System.IO;
using System.IO.Pipes;
using System.Windows;
using IpsaeShared;
using Serilog;

namespace Ipsae.Ipc;

public class IpcClient
{
    private static readonly Lazy<IpcClient> _instance = new(() => new IpcClient());
    public static IpcClient Instance => _instance.Value;
    private const int INTERVAL = 1000;

    private CancellationTokenSource? _cts;

    private IpcClient() { }

    public void StartServiceWorker()
    {
        _cts = new CancellationTokenSource();
        var token = _cts.Token;

        Task.Run(async () =>
        {
            while (!token.IsCancellationRequested)
            {
                var status = await SendCommandAsync(PipeCommand.QueryStatus);
                if (status == null)
                {
                    Log.Warning("Failed to get service status");
                }
                else if (status != ServiceState.Instance.Status)
                {
                    Application.Current.Dispatcher.Invoke(() => ServiceState.Instance.Status = status.Value);
                    Log.Information("Service status updated: {Status}", status.Value);
                }

                try
                {
                    await Task.Delay(INTERVAL, token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }

            Log.Information("Service worker stopped");
        }, token);
    }

    public void Stop()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;
    }

    public async Task<ServiceStatusCode?> SendCommandAsync(PipeCommand command, int timeoutMs = 3000)
    {
        try
        {
            await using var client = new NamedPipeClientStream(".", PipeProtocol.ClientPipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            using var cts = new CancellationTokenSource(timeoutMs);

            await client.ConnectAsync(cts.Token);

            var request = PipeMessage.FromCommand(command);
            var bytes = request.ToBytes();
            await client.WriteAsync(bytes, cts.Token);
            await client.FlushAsync(cts.Token);

            var response = await PipeMessage.ReadAsync(client, cts.Token);
            if (response?.Command == PipeCommand.StatusResponse)
            {
                return response.GetStatusCode();
            }

            Log.Warning("Received invalid response for command {Command}", command);
            return null;
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Failed to send command {Command} to service", command);
            return null;
        }
    }

    public async Task<ServiceStatusCode?> QueryStatusAsync()
    {
        return await SendCommandAsync(PipeCommand.QueryStatus);
    }

    public async Task<ServiceStatusCode?> StartServiceAsync()
    {
        return await SendCommandAsync(PipeCommand.StartService);
    }

    public async Task<ServiceStatusCode?> StopServiceAsync()
    {
        return await SendCommandAsync(PipeCommand.StopService);
    }
}
