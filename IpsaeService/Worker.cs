using System.Diagnostics;
using System.IO.Pipes;
using IpsaeShared;

namespace IpsaeService;

public class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;
    private readonly object _lock = new();

    private volatile ServiceStatusCode _status = ServiceStatusCode.Inactive;
    private volatile EngineCommandCode _pendingEngineCommand = EngineCommandCode.None;

    private const string EnginePath = @"C:\Ipsae\IpsaeEngine\IpsaeEngine.exe";
    private Process? EngineProcess = null;

    #region Main Loop

    public Worker(ILogger<Worker> logger)
    {
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("IpsaeIDS Service starting");
        await Task.Yield();

        var engineTask = EngineManagerLoop(stoppingToken);
        var pipeTask = PipeServerLoop(stoppingToken);

        await Task.WhenAll(engineTask, pipeTask);

        _logger.LogInformation("IpsaeIDS Service stopped");
    }

    #endregion

    #region Client Pipe Server
    private async Task PipeServerLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await using var server = new NamedPipeServerStream(
                    PipeProtocol.ClientPipeName,
                    PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous);

                await server.WaitForConnectionAsync(ct);
                _logger.LogInformation("Client connected");

                await HandleClientAsync(server, ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                _logger.LogWarning("Client manager loop cancellation requested");
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Client pipe error");
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

                var response = HandleClientMessage(message);
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

    private PipeMessage? HandleClientMessage(PipeMessage message)
    {
        switch (message.Command)
        {
            case PipeCommand.QueryStatus:
                return PipeMessage.Status(_status);

            case PipeCommand.StartService:
                _logger.LogInformation("Start command received");
                _pendingEngineCommand = EngineCommandCode.Start;
                Task.Run(StartEngine);
                return PipeMessage.Status(ServiceStatusCode.Starting);

            case PipeCommand.StopService:
                _logger.LogInformation("Stop command received");
                _pendingEngineCommand = EngineCommandCode.Stop;
                return PipeMessage.Status(ServiceStatusCode.Stopping);

            default:
                return null;
        }
    }
    #endregion

    #region Engine Manager
    private async Task EngineManagerLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await using var server = new NamedPipeServerStream(
                    PipeProtocol.EnginePipeName,
                    PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous);

                await server.WaitForConnectionAsync(ct);
                _logger.LogInformation("Engine connected");

                await HandleEngineAsync(server, ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                _logger.LogWarning("Engine manager loop cancellation requested");
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Engine pipe error");
            }
        }

    }

    private async Task HandleEngineAsync(NamedPipeServerStream server, CancellationToken ct)
    {
        try
        {
            while (server.IsConnected && !ct.IsCancellationRequested)
            {
                var message = await PipeMessage.ReadAsync(server, ct);
                if (message == null) break;

                var response = HandleEngineMessage(message);
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
            _logger.LogInformation("Engine disconnected");
        }
    }

    private PipeMessage? HandleEngineMessage(PipeMessage message)
    {
        switch (message.Command)
        {
            case PipeCommand.QueryStatus:
                return PipeMessage.Status(_status);

            case PipeCommand.ActiveEngine:
                _logger.LogInformation("Engine Active Received");
                _status = ServiceStatusCode.Active;
                return ConsumeEngineCommand();

            case PipeCommand.InactiveEngine:
                _logger.LogInformation("Engine Inactive Received");
                _status = ServiceStatusCode.Inactive;
                return ConsumeEngineCommand();

            case PipeCommand.StartingEngine:
                _logger.LogInformation("Engine Starting Received");
                _status = ServiceStatusCode.Starting;
                return ConsumeEngineCommand();

            case PipeCommand.StoppingEngine:
                _logger.LogInformation("Engine Stopping Received");
                _status = ServiceStatusCode.Stopping;
                return ConsumeEngineCommand();

            case PipeCommand.ErrorEngine:
                _logger.LogInformation("Engine Error Received");
                _status = ServiceStatusCode.Error;
                return ConsumeEngineCommand();

            default:
                return null;
        }
    }

    private PipeMessage ConsumeEngineCommand()
    {
        var cmd = _pendingEngineCommand;
        _pendingEngineCommand = EngineCommandCode.None;
        return PipeMessage.EngineCommand(cmd);
    }

    #endregion

    #region Common Functions
    private int StartEngine()
    {
        Process? process;
        try
        {
            _logger.LogInformation("Starting engine: {Path}", EnginePath);

            lock (_lock)
            {
                _status = ServiceStatusCode.Starting;

                process = Process.Start(new ProcessStartInfo
                {
                    FileName = EnginePath,
                    Arguments = $"--db \"{IpsaePaths.DbPath}\" --ini \"{IpsaePaths.IniPath}\" --pipe \"{PipeProtocol.EnginePipeName}\" --log \"{IpsaePaths.EngineLogPath}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                });

                if (process == null || process.HasExited)
                {
                    _logger.LogError("Failed to start engine process");
                    _status = ServiceStatusCode.Inactive;
                    return -1;
                }

                _logger.LogInformation("Engine started (PID: {Pid})", process.Id);
                EngineProcess = process;
            }
            return 1;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to start engine");
            _status = ServiceStatusCode.Inactive;
            return -1;
        }
    }

    private void StopEngine()
    {
        Process? process = EngineProcess;

        if (process == null || process.HasExited)
            return;

        try
        {
            _logger.LogInformation("Stopping engine (PID: {Pid})", process.Id);

            lock (_lock)
            {
                _status = ServiceStatusCode.Stopping;

                if (!process.HasExited)
                {
                    process.Kill(entireProcessTree: true);
                    process.WaitForExit(5000);
                }

                process.Dispose();

                _status = ServiceStatusCode.Inactive;
            }

            _logger.LogInformation("Engine stopped");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error stopping engine");
            _status = ServiceStatusCode.Inactive;
        }
    }
    #endregion
}

