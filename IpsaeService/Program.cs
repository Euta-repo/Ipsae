using IpsaeService;
using IpsaeShared;
using Serilog;

internal class Program
{
    private static async Task Main(string[] args)
    {
        var logPath = Path.Combine(IpsaePaths.LogDir, "ipsae-service-.log");

        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Information()
            .WriteTo.Console()
            .WriteTo.File(logPath,
                rollingInterval: RollingInterval.Day,
                fileSizeLimitBytes: 5 * 1024 * 1024,
                retainedFileCountLimit: 3)
            .CreateLogger();

        try
        {
            Log.Information("IpsaeIDS Service starting");

            var builder = Host.CreateApplicationBuilder(args);
            builder.Services.AddWindowsService(options =>
            {
                options.ServiceName = "IpsaeIDS";
            });
            builder.Services.AddHostedService<Worker>();
            builder.Services.AddSerilog();

            var host = builder.Build();
            await host.RunAsync();
        }
        catch (Exception ex)
        {
            Log.Fatal(ex, "IpsaeIDS Service terminated unexpectedly");
        }
        finally
        {
            await Log.CloseAndFlushAsync();
        }
    }
}
