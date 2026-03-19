using System.ComponentModel;
using System.Windows.Input;
using Ipsae.Ipc;
using IpsaeShared;

namespace Ipsae.ViewModel;

public class ServiceStatusViewModel : ViewModelBase
{
    private readonly INavigationService _navigationService;

    private string _serviceStatusText = GetStatusMessage(ServiceState.Instance.Status);
    private bool _isServiceRunning = ServiceState.Instance.IsRunning;
    private bool _canToggleService = !ServiceState.Instance.IsTransitioning;
    private int _inspectedCount;
    private int _threatCount;
    private string _interfaceName = "eno1";
    private string _uptime = "00:00:00";
    private string _maxDelay = "3 sec";
    private string _logCount = "0 lines";
    private string _footerPackets = "0 packets";
    private bool _isStatusTabActive = true;

    public ServiceStatusViewModel(INavigationService navigationService)
    {
        _navigationService = navigationService;

        ServiceState.Instance.PropertyChanged += OnServiceStateChanged;

        NavigateHomeCommand = new RelayCommand(_ => _navigationService.NavigateHome());
        ToggleServiceCommand = new RelayCommand(_ => ToggleService(), _ => CanToggleService);
        SwitchToStatusTabCommand = new RelayCommand(_ => IsStatusTabActive = true);
        SwitchToStatsTabCommand = new RelayCommand(_ => IsStatusTabActive = false);
    }

    public ICommand NavigateHomeCommand { get; }
    public ICommand ToggleServiceCommand { get; }
    public ICommand SwitchToStatusTabCommand { get; }
    public ICommand SwitchToStatsTabCommand { get; }

    public string ServiceStatusText
    {
        get => _serviceStatusText;
        set => SetProperty(ref _serviceStatusText, value);
    }

    public bool IsServiceRunning
    {
        get => _isServiceRunning;
        set => SetProperty(ref _isServiceRunning, value);
    }

    public bool CanToggleService
    {
        get => _canToggleService;
        set => SetProperty(ref _canToggleService, value);
    }

    public int InspectedCount
    {
        get => _inspectedCount;
        set => SetProperty(ref _inspectedCount, value);
    }

    public int ThreatCount
    {
        get => _threatCount;
        set => SetProperty(ref _threatCount, value);
    }

    public string InterfaceName
    {
        get => _interfaceName;
        set => SetProperty(ref _interfaceName, value);
    }

    public string Uptime
    {
        get => _uptime;
        set => SetProperty(ref _uptime, value);
    }

    public string MaxDelay
    {
        get => _maxDelay;
        set => SetProperty(ref _maxDelay, value);
    }

    public string LogCount
    {
        get => _logCount;
        set => SetProperty(ref _logCount, value);
    }

    public string FooterPackets
    {
        get => _footerPackets;
        set => SetProperty(ref _footerPackets, value);
    }

    public ServiceState State => ServiceState.Instance;

    public bool IsStatusTabActive
    {
        get => _isStatusTabActive;
        set => SetProperty(ref _isStatusTabActive, value);
    }

    private async void ToggleService()
    {
        var state = ServiceState.Instance;
        var ipc = IpcClient.Instance;

        if (state.Status == ServiceStatusCode.Active)
        {
            state.Status = ServiceStatusCode.Stopping;
            var result = await ipc.StopServiceAsync();
            state.Status = result ?? ServiceStatusCode.Inactive;
        }
        else if (state.Status == ServiceStatusCode.Inactive)
        {
            state.Status = ServiceStatusCode.Starting;
            var result = await ipc.StartServiceAsync();
            state.Status = result ?? ServiceStatusCode.Inactive;
        }
    }

    private void OnServiceStateChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(ServiceState.Status))
        {
            var status = ServiceState.Instance.Status;
            IsServiceRunning = status == ServiceStatusCode.Active;
            CanToggleService = !ServiceState.Instance.IsTransitioning;
            ServiceStatusText = GetStatusMessage(status);
        }
    }

    public override void Cleanup()
    {
        ServiceState.Instance.PropertyChanged -= OnServiceStateChanged;
    }

    private static string GetStatusMessage(ServiceStatusCode status) => status switch
    {
        ServiceStatusCode.Active => "잎새가 동작하고 있습니다.",
        ServiceStatusCode.Inactive => "잎새가 중지되었습니다.",
        ServiceStatusCode.Starting => "잎새를 시작하는 중입니다...",
        ServiceStatusCode.Stopping => "잎새를 중지하는 중입니다...",
        _ => "알 수 없는 상태입니다."
    };
}
