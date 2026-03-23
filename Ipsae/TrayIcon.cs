using Hardcodet.Wpf.TaskbarNotification;
using System.Drawing;
using System.Windows;

namespace Ipsae;

public class TrayIcon : IDisposable
{
    private readonly TaskbarIcon _trayIcon;
    private readonly Window _mainWindow;

    public TrayIcon(Window mainWindow)
    {
        _mainWindow = mainWindow;

        _trayIcon = new TaskbarIcon
        {
            ToolTipText = "Ipsae",
            Icon = SystemIcons.Application,  // .ico 있으면 교체
        };

        _trayIcon.TrayMouseDoubleClick += (s, e) => Show();

        // 우클릭 메뉴
        var menu = new System.Windows.Controls.ContextMenu();

        var openItem = new System.Windows.Controls.MenuItem { Header = "열기" };
        openItem.Click += (s, e) => Show();

        var exitItem = new System.Windows.Controls.MenuItem { Header = "종료" };
        exitItem.Click += (s, e) => Exit();

        menu.Items.Add(openItem);
        menu.Items.Add(exitItem);

        _trayIcon.ContextMenu = menu;
    }

    private void Show()
    {
        _mainWindow.Show();
        _mainWindow.WindowState = WindowState.Normal;
        _mainWindow.Activate();
        Application.Current.MainWindow = _mainWindow;
    }

    private void Exit()
    {
        Dispose();
        Application.Current.Shutdown();
    }

    public void Dispose()
    {
        _trayIcon.Dispose();
    }
}