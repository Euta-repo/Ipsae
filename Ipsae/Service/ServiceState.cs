using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Media;
using IpsaeShared;

namespace Ipsae.Service;

public class ServiceState : INotifyPropertyChanged
{
    private static readonly ServiceState _instance = new();
    public static ServiceState Instance => _instance;

    private static readonly SolidColorBrush GreenBrush = new(Color.FromRgb(0x44, 0xAA, 0x55));
    private static readonly SolidColorBrush RedBrush = new(Color.FromRgb(0xCC, 0x55, 0x55));
    private static readonly SolidColorBrush OrangeBrush = new(Color.FromRgb(0xCC, 0x88, 0x33));
    private static readonly Color GreenGlow = Color.FromRgb(0x44, 0xAA, 0x55);
    private static readonly Color RedGlow = Color.FromRgb(0xCC, 0x55, 0x55);
    private static readonly Color OrangeGlow = Color.FromRgb(0xCC, 0x88, 0x33);

    private ServiceStatusCode _status = ServiceStatusCode.Inactive;

    private ServiceState() { }

    public event PropertyChangedEventHandler? PropertyChanged;

    public ServiceStatusCode Status
    {
        get => _status;
        set
        {
            if (_status == value) return;
            _status = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(IsRunning));
            OnPropertyChanged(nameof(IsTransitioning));
            OnPropertyChanged(nameof(StatusText));
            OnPropertyChanged(nameof(StatusSub));
            OnPropertyChanged(nameof(StatusColor));
            OnPropertyChanged(nameof(StatusGlowColor));
            OnPropertyChanged(nameof(StatusLabel));
        }
    }

    public bool IsRunning => _status == ServiceStatusCode.Active;
    public bool IsTransitioning => _status is ServiceStatusCode.Starting or ServiceStatusCode.Stopping;

    public string StatusText => _status switch
    {
        ServiceStatusCode.Active => "Active",
        ServiceStatusCode.Inactive => "Inactive",
        ServiceStatusCode.Starting => "Starting",
        ServiceStatusCode.Stopping => "Stopping",
        _ => "Unknown"
    };

    public string StatusSub => _status switch
    {
        ServiceStatusCode.Active => "동작중",
        ServiceStatusCode.Inactive => "동작 중지",
        ServiceStatusCode.Starting => "시작 중",
        ServiceStatusCode.Stopping => "중지 중",
        _ => "알 수 없음"
    };

    public SolidColorBrush StatusColor => _status switch
    {
        ServiceStatusCode.Active => GreenBrush,
        ServiceStatusCode.Inactive => RedBrush,
        ServiceStatusCode.Starting or ServiceStatusCode.Stopping => OrangeBrush,
        _ => RedBrush
    };

    public Color StatusGlowColor => _status switch
    {
        ServiceStatusCode.Active => GreenGlow,
        ServiceStatusCode.Inactive => RedGlow,
        ServiceStatusCode.Starting or ServiceStatusCode.Stopping => OrangeGlow,
        _ => RedGlow
    };

    public string StatusLabel => _status switch
    {
        ServiceStatusCode.Active => "● MONITORING",
        ServiceStatusCode.Inactive => "● INACTIVE",
        ServiceStatusCode.Starting => "● STARTING",
        ServiceStatusCode.Stopping => "● STOPPING",
        _ => "● UNKNOWN"
    };

    protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
