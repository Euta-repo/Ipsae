using System.Collections.ObjectModel;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Windows.Input;
using Ipsae.Model;
using Ipsae.Service;

namespace Ipsae.ViewModel;

public class SettingsViewModel : ViewModelBase
{
    private readonly INavigationService _navigationService;

    private string _alarmType = "Type 1";
    private bool _runAlertEnabled;
    private bool _autoUpdateEnabled = true;
    private string _threatUpdateInterval = "1 Day";
    private string _maxDelay = "3 Sec";
    private NetworkInterfaceInfo? _selectedInterface;

    public SettingsViewModel(INavigationService navigationService)
    {
        _navigationService = navigationService;

        NavigateHomeCommand = new RelayCommand(_ => _navigationService.NavigateHome());
        ExportCommand = new RelayCommand(_ => Export());
        ImportCommand = new RelayCommand(_ => Import());

        LoadNetworkInterfaces();
    }

    public ICommand NavigateHomeCommand { get; }
    public ICommand ExportCommand { get; }
    public ICommand ImportCommand { get; }

    // ── NIC 인터페이스 목록 ──

    public ObservableCollection<NetworkInterfaceInfo> NetworkInterfaces { get; } = [];

    public NetworkInterfaceInfo? SelectedInterface
    {
        get => _selectedInterface;
        set
        {
            if (SetProperty(ref _selectedInterface, value))
            {
                // INI 저장 시 사용할 값: auto 또는 인터페이스명
                OnPropertyChanged(nameof(SelectedInterfaceConfigValue));
            }
        }
    }

    /// <summary>
    /// INI 설정 파일에 저장될 값
    /// "auto" 또는 실제 인터페이스명 (예: "Ethernet", "Wi-Fi")
    /// </summary>
    public string SelectedInterfaceConfigValue =>
        _selectedInterface is null or { IsAuto: true }
            ? "auto"
            : _selectedInterface.Name;

    // ── 기존 설정 속성들 ──

    public string AlarmType
    {
        get => _alarmType;
        set => SetProperty(ref _alarmType, value);
    }

    public bool RunAlertEnabled
    {
        get => _runAlertEnabled;
        set
        {
            if (SetProperty(ref _runAlertEnabled, value))
            {
                OnPropertyChanged(nameof(RunAlertDisplayText));
            }
        }
    }

    public string RunAlertDisplayText => RunAlertEnabled ? "On" : "Off";

    public bool AutoUpdateEnabled
    {
        get => _autoUpdateEnabled;
        set
        {
            if (SetProperty(ref _autoUpdateEnabled, value))
            {
                OnPropertyChanged(nameof(AutoUpdateDisplayText));
            }
        }
    }

    public string AutoUpdateDisplayText => AutoUpdateEnabled ? "On" : "Off";

    public string ThreatUpdateInterval
    {
        get => _threatUpdateInterval;
        set => SetProperty(ref _threatUpdateInterval, value);
    }

    public string MaxDelay
    {
        get => _maxDelay;
        set => SetProperty(ref _maxDelay, value);
    }

    // ── NIC 목록 조회 ──

    private void LoadNetworkInterfaces()
    {
        // Primary NIC의 IP를 먼저 파악 (라우팅 테이블 기반, 실제 패킷 전송 없음)
        string primaryIp = DetectPrimaryIp();

        string autoDescription = string.IsNullOrEmpty(primaryIp) ? "Auto" : $"Auto";
        string autoDisplayDetail = "";

        // 실제 NIC 목록 수집
        var interfaces = NetworkInterface.GetAllNetworkInterfaces()
            .Where(nic => nic.OperationalStatus == OperationalStatus.Up
                       && nic.NetworkInterfaceType != NetworkInterfaceType.Loopback
                       && nic.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
            .ToList();

        foreach (var nic in interfaces)
        {
            var ipProps = nic.GetIPProperties();
            var ipv4Addr = ipProps.UnicastAddresses
                .FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork);

            string ip = ipv4Addr?.Address.ToString() ?? "";
            string display = string.IsNullOrEmpty(ip)
                ? nic.Name
                : $"{nic.Name}  ({ip})";

            // Primary NIC이면 Auto 표시에 반영
            if (ip == primaryIp)
            {
                autoDisplayDetail = $"Auto  ({nic.Name} - {ip})";
            }

            NetworkInterfaces.Add(new NetworkInterfaceInfo
            {
                Name = nic.Name,
                DisplayName = display,
                IpAddress = ip,
                IsAuto = false
            });
        }

        // Auto 항목을 맨 앞에 삽입
        var autoItem = new NetworkInterfaceInfo
        {
            Name = "auto",
            DisplayName = string.IsNullOrEmpty(autoDisplayDetail) ? "Auto" : autoDisplayDetail,
            IpAddress = primaryIp,
            IsAuto = true
        };
        NetworkInterfaces.Insert(0, autoItem);

        // 기본값: Auto
        SelectedInterface = autoItem;
    }

    /// <summary>
    /// 인터넷에 연결된 Primary NIC의 로컬 IP를 감지한다.
    /// UDP 소켓을 8.8.8.8:53에 Connect하면 OS 라우팅 테이블을 조회해
    /// 실제 인터넷으로 나가는 인터페이스의 로컬 IP를 알 수 있다.
    /// (실제 패킷은 전송되지 않음)
    /// </summary>
    private static string DetectPrimaryIp()
    {
        try
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            socket.Connect("8.8.8.8", 53);
            if (socket.LocalEndPoint is IPEndPoint ep)
                return ep.Address.ToString();
        }
        catch
        {
            // 네트워크 미연결 등
        }
        return "";
    }

    private void Export()
    {
    }

    private void Import()
    {
    }
}
