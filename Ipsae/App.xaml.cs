using System.IO;
using System.Windows;
using Ipsae.Ipc;
using Ipsae.ViewModel;
using IpsaeShared;
using Serilog;

namespace Ipsae;

public partial class App : Application
{
    private static INavigationService? _navigationService;
    private static IpcClient _ipc = IpcClient.Instance;

    public static INavigationService NavigationService
    {
        get => _navigationService ?? throw new InvalidOperationException("NavigationService not initialized");
        set => _navigationService = value;
    }

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // 1. Initialize paths
        IpsaePaths.Initialize();

        // 2. Logger
        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Debug()
            .WriteTo.Console()
            .WriteTo.File(Path.Combine(IpsaePaths.LogDir, "ipsae-ui.log"),
                rollingInterval: RollingInterval.Day,
                fileSizeLimitBytes: 5 * 1024 * 1024,
                retainedFileCountLimit: 3)
            .CreateLogger();

        Log.Information("Ipsae UI starting");

        // 3. Create ini
        if (!File.Exists(IpsaePaths.IniPath))
        {
            try
            {
                File.WriteAllText(IpsaePaths.IniPath, "[Settings]\n");
                Log.Information("Config.ini created at {Path}", IpsaePaths.IniPath);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Failed to create config.ini");
                MessageBox.Show("config.ini 파일을 생성할 수 없습니다.", "파일 오류", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        // 4. Service connection check
        var status = await IpcClient.Instance.QueryStatusAsync();
        if (status == null)
        {
            Log.Error("Service connection failed");
            MessageBox.Show("IpsaeIDS 서비스에 연결할 수 없습니다.", "연결 오류", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }
        Log.Information("Service connected, status: {Status}", status);
        IpcClient.Instance.StartServiceWorker();

        // 5. Database check & create
        if (!DatabaseService.Instance.Initialize())
        {
            MessageBox.Show("데이터베이스 초기화에 실패했습니다.", "DB 오류", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        Log.Information("Ipsae UI exiting");
        Log.CloseAndFlush();

        base.OnExit(e);
    }
}
