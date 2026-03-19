using System.ComponentModel;
using System.Windows;
using System.Windows.Input;
using Ipsae.Ipc;

namespace Ipsae.ViewModel;

public class MainWindowViewModel : ViewModelBase, INavigationService
{
    private ViewModelBase? _currentPageViewModel;
    private bool _isHomeVisible = true;

    private string _serviceStatus = ServiceState.Instance.StatusText;
    private string _eventCount = "1,284 검토";
    private string _eventThreats = "0 THREATS";
    private string _whitelistCount = "3개 등록";
    private string _whitelistEntries = "3 ENTRIES";
    private string _blacklistCount = "1개 등록";
    private string _blacklistEntries = "1 ENTRY";

    public MainWindowViewModel()
    {
        App.NavigationService = this;

        ServiceState.Instance.PropertyChanged += OnServiceStateChanged;

        MinimizeCommand = new RelayCommand(_ =>
            Application.Current.MainWindow.WindowState = WindowState.Minimized);
        MaximizeCommand = new RelayCommand(_ =>
        {
            var w = Application.Current.MainWindow;
            w.WindowState = w.WindowState == WindowState.Maximized
                ? WindowState.Normal : WindowState.Maximized;
        });
        CloseCommand = new RelayCommand(_ =>
            Application.Current.MainWindow.Hide());
        ExitCommand = new RelayCommand(_ =>
            Application.Current.MainWindow.Close());

        NavigateToStatusCommand = new RelayCommand(_ => NavigateTo("ServiceStatus"));
        NavigateToEventsCommand = new RelayCommand(_ => NavigateTo("EventList"));
        NavigateToWhitelistCommand = new RelayCommand(_ => NavigateTo("IpList", "white"));
        NavigateToBlacklistCommand = new RelayCommand(_ => NavigateTo("IpList", "black"));
        NavigateToSettingsCommand = new RelayCommand(_ => NavigateTo("Settings"));
    }

    public ICommand MinimizeCommand { get; }
    public ICommand MaximizeCommand { get; }
    public ICommand CloseCommand { get; }
    public ICommand ExitCommand { get; }
    public ICommand NavigateToStatusCommand { get; }
    public ICommand NavigateToEventsCommand { get; }
    public ICommand NavigateToWhitelistCommand { get; }
    public ICommand NavigateToBlacklistCommand { get; }
    public ICommand NavigateToSettingsCommand { get; }

    public ViewModelBase? CurrentPageViewModel
    {
        get => _currentPageViewModel;
        set
        {
            _currentPageViewModel?.Cleanup();
            if (SetProperty(ref _currentPageViewModel, value))
            {
                IsHomeVisible = value == null;
            }
        }
    }

    public bool IsHomeVisible
    {
        get => _isHomeVisible;
        set => SetProperty(ref _isHomeVisible, value);
    }

    public string ServiceStatus
    {
        get => _serviceStatus;
        set => SetProperty(ref _serviceStatus, value);
    }

    public string EventCount
    {
        get => _eventCount;
        set => SetProperty(ref _eventCount, value);
    }

    public string EventThreats
    {
        get => _eventThreats;
        set => SetProperty(ref _eventThreats, value);
    }

    public string WhitelistCount
    {
        get => _whitelistCount;
        set => SetProperty(ref _whitelistCount, value);
    }

    public string WhitelistEntries
    {
        get => _whitelistEntries;
        set => SetProperty(ref _whitelistEntries, value);
    }

    public string BlacklistCount
    {
        get => _blacklistCount;
        set => SetProperty(ref _blacklistCount, value);
    }

    public string BlacklistEntries
    {
        get => _blacklistEntries;
        set => SetProperty(ref _blacklistEntries, value);
    }

    public ServiceState State => ServiceState.Instance;

    public void NavigateTo(string pageKey, object? parameter = null)
    {
        CurrentPageViewModel = pageKey switch
        {
            "ServiceStatus" => new ServiceStatusViewModel(this),
            "EventList" => new EventListViewModel(this),
            "IpList" => new IpListViewModel(this, parameter as string ?? "white"),
            "Settings" => new SettingsViewModel(this),
            _ => null
        };
    }

    public void NavigateHome()
    {
        CurrentPageViewModel = null;
    }

    private void OnServiceStateChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(ServiceState.Status))
        {
            ServiceStatus = ServiceState.Instance.StatusText;
        }
    }
}
