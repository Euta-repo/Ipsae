namespace IpsaeShared;

public static class PipeProtocol
{
    public const string ClientPipeName = "IpsaeIDS";
    public const string EnginePipeName = "IpsaeEngine";
}

public enum PipeCommand : byte
{
    // Client -> Service (요청: 명령, 응답: 상태)
    QueryStatus = 0x01,
    StartService = 0x02,
    StopService = 0x03,

    // Engine -> Service (요청: 상태 보고)
    InitEngine = 0x10,
    ActiveEngine = 0x11,
    InactiveEngine = 0x12,
    StartingEngine = 0x13,
    StoppingEngine = 0x14,
    ErrorEngine = 0x15,
    WaitingEngine = 0x16,

    // Service -> Client (응답: 상태)
    StatusResponse = 0x81,

    // Service -> Engine (응답: 명령)
    EngineCommand = 0x82,
}

public enum ServiceStatusCode : byte
{
    Active = 0,
    Inactive = 1,
    Starting = 2,
    Stopping = 3,
    Error = 4,
}

public enum EngineCommandCode : byte
{
    None = 0x00,
    Start = 0x01,
    Stop = 0x02,
}
