namespace IpsaeShared;

public static class IpsaePaths
{
    public const string BaseDir = @"C:\Ipsae";
    public const string ConfigDir = @"C:\Ipsae\Config";
    public const string LogDir = @"C:\Ipsae\logs";

    public const string DbPath = @"C:\Ipsae\Config\ipsaedb.db";
    public const string IniPath = @"C:\Ipsae\Config\config.ini";

    public const string EngineFileName = "IpsaeEngine.exe";
    public const string EngineDir = @"C:\Ipsae\IpsaeEngine";
    public const string EnginePath = @"C:\Ipsae\IpsaeEngine\IpsaeEngine.exe";

    public static void Initialize()
    {
        try
        {
            if (!Directory.Exists(BaseDir))
                Directory.CreateDirectory(BaseDir);
            if (!Directory.Exists(ConfigDir))
                Directory.CreateDirectory(ConfigDir);
            if (!Directory.Exists(LogDir))
                Directory.CreateDirectory(LogDir);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("Failed to initialize Ipsae paths", ex);
        }
    }
}
