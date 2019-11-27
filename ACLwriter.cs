using System;
using System.Runtime.InteropServices;

namespace ProtectProcess
{
    [Flags]
    public enum ProcessAccessFlags : uint
    {
        All = 0x001F0FFF,
        Terminate = 0x00000001,
        CreateThread = 0x00000002,
        VirtualMemoryOperation = 0x00000008,
        VirtualMemoryRead = 0x00000010,
        VirtualMemoryWrite = 0x00000020,
        DuplicateHandle = 0x00000040,
        CreateProcess = 0x000000080,
        SetQuota = 0x00000100,
        SetInformation = 0x00000200,
        QueryInformation = 0x00000400,
        QueryLimitedInformation = 0x00001000,
        Synchronize = 0x00100000
    }

    class ACLwriter
    {
        private readonly string sddl;

        private readonly int processId;

        private const uint sd_revision = 1;

        private const int DACL_SECURITY_INFORMATION = 0x00000004;

        public ACLwriter(string sddl, int processId)
        {
            this.sddl = sddl;
            this.processId = processId;
        }

        internal bool SetSecurityDecriptor()
        {
            var hProcess = OpenProcess(ProcessAccessFlags.All, false, processId);

            if (hProcess.Equals(UIntPtr.Zero)) return false;

            var sa = new SECURITY_ATTRIBUTES();
            sa.nLength = Marshal.SizeOf(sa);
            sa.bInheritHandle = 0;

            IntPtr sd_ptr = new IntPtr();
            UIntPtr sd_size_ptr = new UIntPtr();

            if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, sd_revision, out sd_ptr, out sd_size_ptr)) return false;

            int size = checked((int)sd_size_ptr.ToUInt32());
            byte[] managedArray = new byte[size];
            Marshal.Copy(sd_ptr, managedArray, 0, size);

            if (!SetKernelObjectSecurity(hProcess, DACL_SECURITY_INFORMATION, managedArray)) return false;

            return true;
        }

        /// <summary>
        /// The SetKernelObjectSecurity function sets the security of a kernel object. For example, this can be a process, thread, or event.
        /// </summary>
        /// <param name="Handle">A handle to a kernel object for which security information is set.</param>
        /// <param name="securityInformation">A set of bit flags that indicate the type of security information to set. This parameter can be a combination of the SECURITY_INFORMATION bit flags.</param>
        /// <param name="pSecurityDescriptor">A pointer to a SECURITY_DESCRIPTOR structure that contains the new security information.</param>
        /// <returns>If the function succeeds, the function returns nonzero. If the function fails, it returns zero.To get extended error information, call GetLastError.</returns>
        /// <see cref="https://docs.microsoft.com/ja-jp/windows/desktop/api/securitybaseapi/nf-securitybaseapi-setkernelobjectsecurity"/>
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool SetKernelObjectSecurity(IntPtr Handle, int securityInformation, [In] byte[] pSecurityDescriptor);

        /// <summary>
        /// <para>The ConvertStringSecurityDescriptorToSecurityDescriptor function converts a string-format security descriptor into a valid, functional security descriptor.</para>
        /// <para>This function retrieves a security descriptor that the ConvertSecurityDescriptorToStringSecurityDescriptor function converted to string format.</para>
        /// </summary>
        /// <param name="StringSecurityDescriptor">A pointer to a null-terminated string containing the string-format security descriptor to convert.</param>
        /// <param name="StringSDRevision">Specifies the revision level of the StringSecurityDescriptor string. Currently this value must be SDDL_REVISION_1.</param>
        /// <param name="SecurityDescriptor"><para>A pointer to a variable that receives a pointer to the converted security descriptor.</para><para>The returned security descriptor is self-relative. To free the returned buffer, call the LocalFree function.</para><para>To convert the security descriptor to an absolute security descriptor, use the MakeAbsoluteSD function.</para></param>
        /// <param name="SecurityDescriptorSize">A pointer to a variable that receives the size, in bytes, of the converted security descriptor. This parameter can be NULL.</param>
        /// <returns>If the function succeeds, the return value is nonzero.If the function fails, the return value is zero.To get extended error information, call GetLastError.GetLastError may return one of the following error codes.</returns>
        /// <see cref="https://docs.microsoft.com/ja-jp/windows/desktop/api/sddl/nf-sddl-convertstringsecuritydescriptortosecuritydescriptora"/>
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
            string StringSecurityDescriptor,
            uint StringSDRevision,
            out IntPtr SecurityDescriptor,
            out UIntPtr SecurityDescriptorSize
        );

        /// <summary>
        /// <para>The SECURITY_ATTRIBUTES structure contains the security descriptor for an object and specifies whether the handle retrieved by specifying this structure is inheritable.</para>
        /// <para>This structure provides security settings for objects created by various functions, such as CreateFile, CreatePipe, CreateProcess, RegCreateKeyEx, or RegSaveKeyEx.</para>
        /// <see cref="https://docs.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa379560(v%3Dvs.85)"/>
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            /// <summary>
            /// The size, in bytes, of this structure. Set this value to the size of the SECURITY_ATTRIBUTES structure.
            /// </summary>
            public int nLength;
            /// <summary>
            /// <para>A pointer to a SECURITY_DESCRIPTOR structure that controls access to the object.</para>
            /// <para>If the value of this member is NULL, the object is assigned the default security descriptor associated with the access token of the calling process.</para>
            /// <para>This is not the same as granting access to everyone by assigning a NULL discretionary access control list (DACL).</para>
            /// <para>By default, the default DACL in the access token of a process allows access only to the user represented by the access token.</para>
            /// </summary>
            public IntPtr lpSecurityDescriptor;
            /// <summary>
            /// A Boolean value that specifies whether the returned handle is inherited when a new process is created. If this member is TRUE, the new process inherits the handle.
            /// </summary>
            public int bInheritHandle;
        }

        /// <summary>
        /// Opens an existing local process object.
        /// </summary>
        /// <param name="processAccess"><para>The access to the process object. This access right is checked against the security descriptor for the process.</para><para>This parameter can be one or more of the process access rights.If the caller has enabled the SeDebugPrivilege privilege, the requested access is granted regardless of the contents of the security descriptor.</para></param>
        /// <param name="bInheritHandle">If this value is TRUE, processes created by this process will inherit the handle. Otherwise, the processes do not inherit this handle.</param>
        /// <param name="processId"><para>The identifier of the local process to be opened.</para><para>If the specified process is the System Process (0x00000000), the function fails and the last error code is ERROR_INVALID_PARAMETER.</para><para>If the specified process is the Idle process or one of the CSRSS processes, this function fails and the last error code is ERROR_ACCESS_DENIED because their access restrictions prevent user-level code from opening them.</para><para>If you are using GetCurrentProcessId as an argument to this function, consider using GetCurrentProcess instead of OpenProcess, for improved performance.</para></param>
        /// <returns>If the function succeeds, the return value is an open handle to the specified process. If the function fails, the return value is NULL.To get extended error information, call GetLastError.</returns>
        /// <see cref=">https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-openprocess"/>
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
            ProcessAccessFlags processAccess,
            bool bInheritHandle,
            int processId
        );
    }
}
