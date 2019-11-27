using System;
using System.Runtime.InteropServices;

namespace ProtectProcess
{
    public enum SW
    {
        SW_HIDE = 0,
        SW_SHOWNORMAL = 1,
        SW_SHOWMINIMIZED = 2,
        SW_SHOWMAXIMIZED = 3,
        SW_SHOWNOACTIVATE = 4,
        SW_SHOW = 5,
        SW_MINIMIZE = 6,
        SW_SHOWMINNOACTIVE = 7,
        SW_SHOWNA = 8,
        SW_RESTORE = 9,
        SW_SHOWDEFAULT = 10,
        SW_FORCEMINIMIZE = 11
    }

    class ConsoleVisibility
    {
        public static void SetVisibility(int nCmdShow)
        {
            ShowWindow(GetConsoleWindow(), nCmdShow);
        }

        /// <summary>
        /// Retrieves the window handle used by the console associated with the calling process.
        /// </summary>
        /// <see cref="https://docs.microsoft.com/ja-jp/windows/console/getconsolewindow"/>
        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();

        /// <summary>
        /// Sets the specified window's show state.
        /// </summary>
        /// <param name="hWnd">
        /// A handle to the window.
        /// </param>
        /// <param name="nCmdShow">
        /// <para>Controls how the window is to be shown.</para>
        /// <para>This parameter is ignored the first time an application calls ShowWindow,</para>
        /// <para>if the program that launched the application provides a STARTUPINFO structure.</para>
        /// <para>Otherwise, the first time ShowWindow is called,</para>
        /// <para>the value should be the value obtained by the WinMain function in its nCmdShow parameter.</para>
        /// <para>In subsequent calls, this parameter can be one of the following values.</para>
        /// </param>
        /// <returns>
        /// If the window was previously visible, the return value is nonzero.
        /// If the window was previously hidden, the return value is zero.
        /// </returns>
        /// <see cref="https://docs.microsoft.com/ja-jp/windows/desktop/api/winuser/nf-winuser-showwindow"/>
        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    }
}
