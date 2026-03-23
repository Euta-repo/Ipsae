using System;
using System.Windows.Forms;

namespace WinFormsApp1
{
    public partial class Form1 : Form
    {
        private NotifyIcon trayIcon;
        private ContextMenuStrip trayMenu;

        public Form1()
        {
            InitializeComponent();
            InitializeTray();
        }

        private void InitializeTray()
        {
            // Create a tray menu
            trayMenu = new ContextMenuStrip();
            trayMenu.Items.Add("열기", null, onClick);
            trayMenu.Items.Add("종료", null, closeClick);

            // Create a tray icon
            trayIcon = new NotifyIcon();
            trayIcon.Text = "My Tray App";
            trayIcon.Icon = SystemIcons.Application; // Use a default icon
            trayIcon.ContextMenuStrip = trayMenu;
            trayIcon.Visible = true;
            trayIcon.DoubleClick += onClick;
        }
        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            // Hide the form instead of closing it
            if (e.CloseReason == CloseReason.UserClosing)
            {
                e.Cancel = true;       // 실제 종료 취소
                this.Hide();           // 창만 숨김
                trayIcon.ShowBalloonTip(1000, "알림", "트레이에서 실행 중입니다.", ToolTipIcon.Info);
            }
            else
            {
                base.OnFormClosing(e);
            }
        }

        private void onClick(object sender, EventArgs e)
        {
            this.Show();
            this.WindowState = FormWindowState.Normal;
            this.BringToFront();
        }

        private void closeClick(object sender, EventArgs e)
        {
            trayIcon.Visible = false; // Hide the tray icon
            Application.Exit(); // Exit the application
        }
    }
}
