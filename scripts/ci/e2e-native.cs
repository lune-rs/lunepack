// Native helpers of the Windows end-to-end scripts (scripts/e2e-windows.ps1,
// scripts/ci/console-ctrl-test.ps1), compiled in memory with Add-Type. C# 5 syntax only, so that
// Windows PowerShell 5.1 (csc) and PowerShell 7 (Roslyn) both accept it.
//
// Lpe2eProc starts a process with chosen creation flags (a new console, a new process group, no
// console at all) and reads its exit code. Lpe2eSnap samples the process table for the console
// host (conhost.exe) children of two named programs.
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public static class Lpe2eProc
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CreateProcessW(string application, StringBuilder commandLine, IntPtr processAttributes,
        IntPtr threadAttributes, bool inheritHandles, uint flags, IntPtr environment, string directory,
        ref STARTUPINFO startup, out PROCESS_INFORMATION info);

    [DllImport("kernel32.dll")]
    static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("kernel32.dll")]
    static extern bool GetExitCodeProcess(IntPtr handle, out uint code);

    [DllImport("kernel32.dll")]
    static extern bool TerminateProcess(IntPtr handle, uint code);

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetConsoleCtrlHandler(IntPtr handler, bool add);

    // A process that was started with Ctrl+C disabled (the flag a parent set with
    // SetConsoleCtrlHandler(NULL, TRUE), or a new process group, is inherited by every child) hands
    // that on. This clears it in the caller, so the programs it starts next handle Ctrl+C normally.
    public static bool EnableCtrlC()
    {
        return SetConsoleCtrlHandler(IntPtr.Zero, false);
    }

    public const uint NewConsole = 0x10;
    public const uint NewProcessGroup = 0x200;
    public const uint Detached = 0x8;

    // Starts `commandLine` (hidden window, the caller's environment and directory); returns the
    // process handle and sets `pid`.
    public static IntPtr Start(string commandLine, uint flags, out int pid)
    {
        STARTUPINFO startup = new STARTUPINFO();
        startup.cb = Marshal.SizeOf(typeof(STARTUPINFO));
        startup.dwFlags = 1; // STARTF_USESHOWWINDOW
        startup.wShowWindow = 0; // SW_HIDE
        PROCESS_INFORMATION info;
        StringBuilder line = new StringBuilder(commandLine);
        if (!CreateProcessW(null, line, IntPtr.Zero, IntPtr.Zero, false, flags, IntPtr.Zero, null, ref startup, out info))
        {
            throw new InvalidOperationException("CreateProcess failed: " + Marshal.GetLastWin32Error());
        }
        CloseHandle(info.hThread);
        pid = info.dwProcessId;
        return info.hProcess;
    }

    public static bool Exited(IntPtr handle, int milliseconds)
    {
        return WaitForSingleObject(handle, (uint)milliseconds) == 0;
    }

    public static uint ExitCode(IntPtr handle)
    {
        uint code;
        GetExitCodeProcess(handle, out code);
        return code;
    }

    public static void Kill(IntPtr handle)
    {
        TerminateProcess(handle, 1);
    }

    public static void Close(IntPtr handle)
    {
        CloseHandle(handle);
    }
}

public static class Lpe2eSnap
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct PROCESSENTRY32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "Process32FirstW")]
    static extern bool Process32First(IntPtr snapshot, ref PROCESSENTRY32 entry);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "Process32NextW")]
    static extern bool Process32Next(IntPtr snapshot, ref PROCESSENTRY32 entry);

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr handle);

    // For `milliseconds`, snapshots the process table every few milliseconds and counts the
    // distinct processes named `runtimeName` and `controlName` it ever saw, and the distinct
    // conhost.exe processes whose parent was one of each. Returns
    // { runtimes seen, console hosts under a runtime, controls seen, console hosts under a control }.
    public static int[] Watch(string runtimeName, string controlName, int milliseconds)
    {
        Dictionary<uint, bool> runtimes = new Dictionary<uint, bool>();
        Dictionary<uint, bool> controls = new Dictionary<uint, bool>();
        Dictionary<uint, bool> hostsUnderRuntime = new Dictionary<uint, bool>();
        Dictionary<uint, bool> hostsUnderControl = new Dictionary<uint, bool>();
        DateTime end = DateTime.UtcNow.AddMilliseconds(milliseconds);
        while (DateTime.UtcNow < end)
        {
            IntPtr snapshot = CreateToolhelp32Snapshot(2, 0); // TH32CS_SNAPPROCESS
            if (snapshot != IntPtr.Zero && snapshot != new IntPtr(-1))
            {
                Dictionary<uint, string> names = new Dictionary<uint, string>();
                List<uint[]> hosts = new List<uint[]>();
                PROCESSENTRY32 entry = new PROCESSENTRY32();
                entry.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32));
                bool more = Process32First(snapshot, ref entry);
                while (more)
                {
                    string name = entry.szExeFile.ToLowerInvariant();
                    names[entry.th32ProcessID] = name;
                    if (name == "conhost.exe")
                    {
                        hosts.Add(new uint[] { entry.th32ProcessID, entry.th32ParentProcessID });
                    }
                    more = Process32Next(snapshot, ref entry);
                }
                CloseHandle(snapshot);
                foreach (uint id in names.Keys)
                {
                    if (names[id] == runtimeName) { runtimes[id] = true; }
                    if (names[id] == controlName) { controls[id] = true; }
                }
                foreach (uint[] host in hosts)
                {
                    string parent;
                    if (names.TryGetValue(host[1], out parent))
                    {
                        if (parent == runtimeName) { hostsUnderRuntime[host[0]] = true; }
                        if (parent == controlName) { hostsUnderControl[host[0]] = true; }
                    }
                }
            }
            System.Threading.Thread.Sleep(4);
        }
        return new int[] { runtimes.Count, hostsUnderRuntime.Count, controls.Count, hostsUnderControl.Count };
    }
}
