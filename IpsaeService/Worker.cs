using IpsaeShared;
using System.Diagnostics;
using System.IO.Pipes;

namespace IpsaeService;

public class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;
    private readonly object _lock = new();

    private ServiceStatusCode _status = ServiceStatusCode.Inactive;
    private EngineCommandCode _pendingEngineCommand = EngineCommandCode.None;

    private Process? EngineProcess = null;
    private int _engineRestartCount = 0;
    private const int MaxEngineRestarts = 3;

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

        StopEngineForce();

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
                _status = ServiceStatusCode.Starting;
                StopEngineForce();
                Task.Run(StartEngine);
                return PipeMessage.Status(ServiceStatusCode.Starting);

            case PipeCommand.StopService:
                _logger.LogInformation("Stop command received");
                _pendingEngineCommand = EngineCommandCode.Stop;
                _status = ServiceStatusCode.Stopping;
                StartStopTimeout();
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
                _engineRestartCount = 0;

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

    private const int EngineReadTimeoutMs = 3000;

    private async Task HandleEngineAsync(NamedPipeServerStream server, CancellationToken ct)
    {
        try
        {
            while (server.IsConnected && !ct.IsCancellationRequested)
            {
                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeoutCts.CancelAfter(EngineReadTimeoutMs);

                PipeMessage? message;
                try
                {
                    message = await PipeMessage.ReadAsync(server, timeoutCts.Token);
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    _engineRestartCount++;
                    _logger.LogWarning("Engine read timeout ({Seconds}s). Restart attempt {Count}/{Max}.",
                        EngineReadTimeoutMs / 1000, _engineRestartCount, MaxEngineRestarts);

                    StopEngineForce();

                    if (_engineRestartCount >= MaxEngineRestarts)
                    {
                        _logger.LogError("Engine restart limit reached. Giving up.");
                        _status = ServiceStatusCode.Error;
                        break;
                    }

                    StartEngine();
                    break; // EngineManagerLoop에서 새 파이프 연결을 대기
                }

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
        ServiceStatusCode? status = null;
        bool isReset = false;

        switch (message.Command)
        {
            case PipeCommand.QueryStatus:
                return ConsumeEngineCommand(ref _pendingEngineCommand, isReset);

            case PipeCommand.ActiveEngine:
                _logger.LogInformation("Engine Active Received");
                status = ServiceStatusCode.Active;

                break;

            case PipeCommand.InactiveEngine:
                _logger.LogInformation("Engine Inactive Received");
                status = ServiceStatusCode.Inactive;
                break;

            case PipeCommand.StartingEngine:
                _logger.LogInformation("Engine Starting Received");
                status = ServiceStatusCode.Starting;
                break;

            case PipeCommand.StoppingEngine:
                _logger.LogInformation("Engine Stopping Received");
                status = ServiceStatusCode.Stopping;
                break;

            case PipeCommand.ErrorEngine:
                _logger.LogInformation("Engine Error Received");
                status = ServiceStatusCode.Error;
                break;

            default:
                return null;
        }
        if (ShouldUpdateStatus(_pendingEngineCommand, status))
        {
            isReset = _pendingEngineCommand != EngineCommandCode.None ? true : false;
            _status = status ?? _status;
            _logger.LogInformation("Service status updated: {Status}", _status);
        }  

        return ConsumeEngineCommand(ref _pendingEngineCommand, isReset);
    }

    private PipeMessage ConsumeEngineCommand(ref EngineCommandCode cmd, bool isReset)
    {
        lock (_lock)
        {
            var result = PipeMessage.EngineCommand(cmd);
            cmd = isReset ? EngineCommandCode.None : cmd;
            return result;
        }
    }

    #endregion

    #region Common Functions

    private const int StopTimeoutMs = 30000;

    private void StartStopTimeout()
    {
        Task.Run(async () =>
        {
            await Task.Delay(StopTimeoutMs);
            if (_status == ServiceStatusCode.Stopping)
            {
                _logger.LogWarning("Engine stop timeout ({Seconds}s). Force killing engine.", StopTimeoutMs / 1000);
                StopEngineForce();
            }
        });
    }

    private int StartEngine()
    {
        Process? process;
        try
        {
            _logger.LogInformation("Starting engine: {Path}", IpsaePaths.EnginePath);

            lock (_lock)
            {
                _status = ServiceStatusCode.Starting;

                process = Process.Start(new ProcessStartInfo
                {
                    FileName = IpsaePaths.EnginePath,
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

    private void StopEngineForce()
    {
        _status = ServiceStatusCode.Stopping;

        // 1. 관리 중인 프로세스 종료
        try
        {
            var process = EngineProcess;
            if (process != null && !process.HasExited)
            {
                _logger.LogInformation("Stopping engine (PID: {Pid})", process.Id);
                process.Kill(entireProcessTree: true);
                process.WaitForExit(5000);
            }
            process?.Dispose();
            EngineProcess = null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error stopping managed engine process");
        }

        // 2. PC에서 모든 IpsaeEngine.exe 프로세스 종료
        var engineName = Path.GetFileNameWithoutExtension(IpsaePaths.EngineFileName);
        try
        {
            foreach (var proc in Process.GetProcessesByName(engineName))
            {
                try
                {
                    _logger.LogWarning("Killing orphan engine process (PID: {Pid})", proc.Id);
                    proc.Kill(entireProcessTree: true);
                    proc.WaitForExit(5000);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to kill engine process (PID: {Pid})", proc.Id);
                }
                finally
                {
                    proc.Dispose();
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error enumerating engine processes");
        }

        _status = ServiceStatusCode.Inactive;
        _logger.LogInformation("Engine stopped");
    }

    private bool ShouldUpdateStatus(EngineCommandCode cmd, ServiceStatusCode? newStatus)
    {
        return (cmd, newStatus) switch
        {
            (EngineCommandCode.Stop, ServiceStatusCode.Stopping) => true,
            (EngineCommandCode.Stop, ServiceStatusCode.Inactive) => true,
            (EngineCommandCode.Stop, ServiceStatusCode.Error) => true,
            (EngineCommandCode.Stop, _) => false,
            (EngineCommandCode.Start, ServiceStatusCode.Starting) => true,
            (EngineCommandCode.Start, ServiceStatusCode.Error) => true,
            (EngineCommandCode.Start, ServiceStatusCode.Active) => true,
            (EngineCommandCode.Start, _) => false,
            _ => true,
        };
    }
    #endregion
}

