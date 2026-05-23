using System.Collections.ObjectModel;
using System.Windows.Input;
using System.Windows.Threading;
using Ipsae.Ipc;
using Ipsae.Model;

namespace Ipsae.ViewModel;

public class EventListViewModel : ViewModelBase
{
    private readonly INavigationService _navigationService;
    private readonly DispatcherTimer _pollTimer;

    private int _totalCount;

    public EventListViewModel(INavigationService navigationService)
    {
        _navigationService = navigationService;

        NavigateHomeCommand = new RelayCommand(_ => _navigationService.NavigateHome());

        LoadProcessLogs();

        _pollTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
        _pollTimer.Tick += (_, _) => LoadProcessLogs();
        _pollTimer.Start();
    }

    public ICommand NavigateHomeCommand { get; }

    public ObservableCollection<DetectionEvent> Events { get; } = new();

    public int TotalCount
    {
        get => _totalCount;
        set => SetProperty(ref _totalCount, value);
    }

    private void LoadProcessLogs()
    {
        var logs = DatabaseService.Instance.GetProcessLogs();

        Events.Clear();
        foreach (var log in logs)
            Events.Add(log);

        TotalCount = Events.Count;
    }

    public override void Cleanup()
    {
        _pollTimer.Stop();
    }
}
