using System.Threading;
using System.Diagnostics;

namespace ProtectProcess
{
    class NotificationManagerActivator
    {
        static void Main(string[] args)
        {
            ConsoleVisibility.SetVisibility((int)SW.SW_HIDE);

            /// https://blogs.technet.microsoft.com/askds/2008/04/18/the-security-descriptor-definition-language-of-love-part-1/
            /// https://blogs.technet.microsoft.com/askds/2008/05/07/the-security-descriptor-definition-language-of-love-part-2/
            var acl = new ACLwriter("D:P(D;OICI;GA;;;BG)(D;OICI;GA;;;AN)", Process.GetCurrentProcess().Id);
            acl.SetSecurityDecriptor();

            while(true)
            {
                Process[] pname = Process.GetProcessesByName(Properties.Settings.Default.FILE_NAME);
                if (pname.Length == 0) Process.Start(Properties.Settings.Default.FILE_PATH);
                Thread.Sleep(2000);
            }
        }
    }
}
