// The stand-in console app of the Windows end-to-end suite (scripts/e2e-windows.ps1): compiled
// with the .NET Framework's csc.exe, packed as the entry of a `terminal = true` app, and run
// through the console stub.
//
//   --echo <text>    write <text> to standard output (no newline)
//   --eecho <text>   write <text> to standard error
//   --cat            copy standard input to standard output
//   --exit <n>       the exit code to end with
//   --hold           write `ready`, then wait; Ctrl+C or Ctrl+Break is handled: write
//                    `event <key>`, wait one second, exit 42
//   --parent         start this program with --hold and wait for it, with no handler of its own
//                    (the control: a parent that does not protect itself dies of the event)
//
// `ready` and `event ...` lines go to the file the environment variable LUNEPACK_E2E_OUT names.
using System;
using System.Diagnostics;
using System.IO;
using System.Threading;

public static class Ctl
{
    static void Note(string line)
    {
        string path = Environment.GetEnvironmentVariable("LUNEPACK_E2E_OUT");
        if (!String.IsNullOrEmpty(path))
        {
            File.AppendAllText(path, line + "\n");
        }
    }

    static int Hold()
    {
        Console.CancelKeyPress += delegate(object sender, ConsoleCancelEventArgs e)
        {
            e.Cancel = true;
            Note("event " + e.SpecialKey);
            Thread.Sleep(1000);
            Environment.Exit(42);
        };
        Note("ready");
        Thread.Sleep(60000);
        Note("timeout");
        return 3;
    }

    static int Parent()
    {
        string self = Process.GetCurrentProcess().MainModule.FileName;
        ProcessStartInfo info = new ProcessStartInfo(self, "--hold");
        info.UseShellExecute = false;
        using (Process child = Process.Start(info))
        {
            child.WaitForExit();
            return child.ExitCode;
        }
    }

    public static int Main(string[] args)
    {
        int exit = 0;
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--hold":
                    return Hold();
                case "--parent":
                    return Parent();
                case "--echo":
                    Console.Out.Write(args[++i]);
                    Console.Out.Flush();
                    break;
                case "--eecho":
                    Console.Error.Write(args[++i]);
                    Console.Error.Flush();
                    break;
                case "--cat":
                    Console.Out.Write(Console.In.ReadToEnd());
                    Console.Out.Flush();
                    break;
                case "--exit":
                    exit = Int32.Parse(args[++i]);
                    break;
            }
        }
        return exit;
    }
}
