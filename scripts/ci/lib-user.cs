using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

// Runs one command line as another local account without the Task Scheduler and without loading
// the account's profile: a batch logon token, a process made with it, and an access entry for the
// account on this process's window station and desktop (without it the new process dies at start
// with 0xC0000142 in a non-interactive session). Everything is released when Run returns.
public static class LpRun {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO {
        public int cb; public string lpReserved, lpDesktop, lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool LogonUserW(string user, string domain, string password, int type, int provider, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessWithTokenW(IntPtr token, int logonFlags, string app, string cmd, int flags, IntPtr env, string dir, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
    [DllImport("user32.dll")] static extern IntPtr GetProcessWindowStation();
    [DllImport("user32.dll")] static extern IntPtr GetThreadDesktop(int threadId);
    [DllImport("kernel32.dll")] static extern int GetCurrentThreadId();
    [DllImport("user32.dll", SetLastError = true)]
    static extern bool GetUserObjectSecurity(IntPtr obj, ref int info, byte[] sd, int length, out int needed);
    [DllImport("user32.dll", SetLastError = true)]
    static extern bool SetUserObjectSecurity(IntPtr obj, ref int info, byte[] sd);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr h, uint ms);
    [DllImport("kernel32.dll")] static extern bool GetExitCodeProcess(IntPtr h, out uint code);
    [DllImport("kernel32.dll")] static extern bool TerminateProcess(IntPtr h, uint code);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);

    const int DACL_SECURITY_INFORMATION = 4;
    const int WINSTA_ALL = 0x37F | 0x20000;   // WINSTA_ALL_ACCESS | READ_CONTROL
    const int DESKTOP_ALL = 0x1FF | 0x20000;  // DESKTOP_ALL | READ_CONTROL

    // Adds (grant) or removes (not grant) the account's entry on a window station or desktop.
    static string Edit(IntPtr obj, SecurityIdentifier sid, int mask, bool grant) {
        int info = DACL_SECURITY_INFORMATION, needed;
        GetUserObjectSecurity(obj, ref info, null, 0, out needed);
        var buffer = new byte[needed];
        if (!GetUserObjectSecurity(obj, ref info, buffer, buffer.Length, out needed))
            return "read the security failed (" + Marshal.GetLastWin32Error() + ")";
        var sd = new RawSecurityDescriptor(buffer, 0);
        var dacl = sd.DiscretionaryAcl;
        if (dacl == null) return null;
        for (int i = dacl.Count - 1; i >= 0; i--) {
            var ace = dacl[i] as CommonAce;
            if (ace != null && ace.SecurityIdentifier == sid) dacl.RemoveAce(i);
        }
        if (grant) dacl.InsertAce(0, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, mask, sid, false, null));
        var bytes = new byte[sd.BinaryLength];
        sd.GetBinaryForm(bytes, 0);
        if (!SetUserObjectSecurity(obj, ref info, bytes))
            return "set the security failed (" + Marshal.GetLastWin32Error() + ")";
        return null;
    }

    // Gives the account (or takes from it) access to this process's window station and desktop;
    // returns null on success, otherwise what failed.
    public static string Access(string sidText, bool grant) {
        var sid = new SecurityIdentifier(sidText);
        return Edit(GetProcessWindowStation(), sid, WINSTA_ALL, grant)
            ?? Edit(GetThreadDesktop(GetCurrentThreadId()), sid, DESKTOP_ALL, grant);
    }

    // Runs `cmdline` as `user` with a batch logon token and no window; returns the exit code, or
    // -2 (logon failed), -3 (the process could not be made) or -1 (timed out; the process is
    // ended). `error` carries the Windows error code of a -2 or -3.
    public static int Run(string user, string password, string cmdline, string dir, int timeoutMs, out int error) {
        error = 0;
        IntPtr token;
        if (!LogonUserW(user, ".", password, 4, 0, out token)) { error = Marshal.GetLastWin32Error(); return -2; }
        try {
            var si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            PROCESS_INFORMATION pi;
            // CREATE_NO_WINDOW; a null environment: the new process gets the one the system builds
            // for the token.
            if (!CreateProcessWithTokenW(token, 0, null, cmdline, 0x08000000, IntPtr.Zero, dir, ref si, out pi)) {
                error = Marshal.GetLastWin32Error();
                return -3;
            }
            try {
                if (WaitForSingleObject(pi.hProcess, (uint)timeoutMs) != 0) {
                    TerminateProcess(pi.hProcess, 1);
                    return -1;
                }
                uint code;
                GetExitCodeProcess(pi.hProcess, out code);
                return (int)code;
            } finally { CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }
        } finally { CloseHandle(token); }
    }
}

// Adds or removes one account right (for example SeBatchLogonRight) of one SID.
public static class LpLsa {
    [StructLayout(LayoutKind.Sequential)] struct LSA_UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }
    [StructLayout(LayoutKind.Sequential)] struct LSA_OBJECT_ATTRIBUTES { public int Length; public IntPtr RootDirectory; public IntPtr ObjectName; public int Attributes; public IntPtr SecurityDescriptor; public IntPtr SecurityQualityOfService; }
    [DllImport("advapi32.dll")] static extern uint LsaOpenPolicy(IntPtr system, ref LSA_OBJECT_ATTRIBUTES attrs, uint access, out IntPtr policy);
    [DllImport("advapi32.dll")] static extern uint LsaAddAccountRights(IntPtr policy, byte[] sid, LSA_UNICODE_STRING[] rights, uint count);
    [DllImport("advapi32.dll")] static extern uint LsaRemoveAccountRights(IntPtr policy, byte[] sid, bool all, LSA_UNICODE_STRING[] rights, uint count);
    [DllImport("advapi32.dll")] static extern uint LsaClose(IntPtr policy);
    static LSA_UNICODE_STRING Str(string s) {
        var u = new LSA_UNICODE_STRING();
        u.Buffer = Marshal.StringToHGlobalUni(s);
        u.Length = (ushort)(s.Length * 2);
        u.MaximumLength = (ushort)(s.Length * 2 + 2);
        return u;
    }
    // Returns the NTSTATUS (0 is success).
    public static uint Change(string sidText, string right, bool add) {
        var sid = new SecurityIdentifier(sidText);
        var bytes = new byte[sid.BinaryLength];
        sid.GetBinaryForm(bytes, 0);
        var attrs = new LSA_OBJECT_ATTRIBUTES();
        IntPtr policy;
        uint st = LsaOpenPolicy(IntPtr.Zero, ref attrs, 0x811, out policy);
        if (st != 0) return st;
        var rights = new LSA_UNICODE_STRING[] { Str(right) };
        st = add ? LsaAddAccountRights(policy, bytes, rights, 1) : LsaRemoveAccountRights(policy, bytes, false, rights, 1);
        LsaClose(policy);
        return st;
    }
}
