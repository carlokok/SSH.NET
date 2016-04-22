using System.Runtime.InteropServices;

namespace Renci.SshNet.Pageant
{
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    internal struct COPYDATASTRUCT
    {
        public COPYDATASTRUCT(int dwData, string lpData)
        {
            this.dwData = (System.IntPtr)dwData;
            this.lpData = lpData;
            cbData = (System.IntPtr)(lpData.Length + 1);
        }


        private readonly System.IntPtr dwData;

        private readonly System.IntPtr cbData;

        [MarshalAs(UnmanagedType.LPStr)] private readonly string lpData;
    }
}