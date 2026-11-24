// The .NET example app: the same app as the shell app of the end-to-end suite
// (crates/lunepack-runtime/tests/e2e/shell-app/app.sh), written against the runtime's command line
// only (docs/RUNTIME.md).
//
// At every start it runs `startup --json -- <its arguments>` first and exits when the action is
// "exit"; then it acts on the marker file `e2e-flags` at its tree's root (crash-on-start,
// exit-without-confirm, slow-confirm <secs>, hold <secs>), confirms its health, and with `--update`
// runs check, download and apply-and-restart (with `--no-ui` as well, the call carries `--no-ui`: no
// update window). Outcomes go to the file LUNEPACK_E2E_OUT as `<tree version> <outcome>`, the
// executable's real path to LUNEPACK_E2E_DETAIL (neither is written when its variable is unset).
//
// The runtime is the file `lunepack-runtime` beside this program's own executable, found from
// Environment.ProcessPath (never AppContext.BaseDirectory, the working directory or PATH: on macOS
// the managed files sit under Contents/Resources/app while the host sits in Contents/MacOS). The
// runtime is started with an argument list, no shell.
//
// No path ends in an unhandled exception, Environment.FailFast or an abort (a crash dialog on macOS):
// "crash on start" is Environment.Exit with a non-zero code, and the top-level catch writes
// `error unhandled` and exits non-zero.

using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace Example;

internal static class Program
{
    private static int Main(string[] args)
    {
        var app = new App(args);
        try
        {
            return app.Run();
        }
        catch (Exception)
        {
            try
            {
                app.Out("error unhandled");
            }
            catch (Exception)
            {
                // Nothing more can be said.
            }
            return 1;
        }
    }
}

internal sealed class App(string[] args)
{
    // The exit code `confirm` gives for a health token that does not match (docs/RUNTIME.md,
    // "Exit codes"); every other non-zero code is an error of its command.
    private const int TokenMismatch = 16;

    private static readonly UTF8Encoding Utf8 = new(false);

    private string version = "-";
    private string runtime = "";
    private int rc;
    private string last = "";

    public int Run()
    {
        var processPath = Environment.ProcessPath;
        var self = processPath is null ? null : RealPath(processPath);
        var dir = self is null ? null : Path.GetDirectoryName(self);
        if (self is null || dir is null)
        {
            Out("error locate");
            return 1;
        }
        runtime = Path.Combine(dir, OperatingSystem.IsWindows() ? "lunepack-runtime.exe" : "lunepack-runtime");
        if (!IsExecutable(runtime))
        {
            Out("error locate");
            return 1;
        }

        var startupArgs = new List<string> { "startup", "--json", "--" };
        startupArgs.AddRange(args);
        Call(startupArgs);
        var startup = LastObject();
        var treeVersion = Member(startup, "tree_version");
        version = treeVersion.Length > 0 ? treeVersion : "-";
        if (rc != 0 || startup is null)
        {
            Out("error startup");
            return 1;
        }

        Detail($"exe {self}");
        Out("start");

        var update = false;
        var noUi = false;
        var background = false;
        foreach (var arg in args)
        {
            switch (arg)
            {
                case "--after-update":
                    Out("arg after-update");
                    break;
                case "--update":
                    update = true;
                    break;
                case "--no-ui":
                    noUi = true;
                    break;
                case "--background":
                    background = true;
                    break;
            }
        }

        // The events, oldest first.
        if (startup.Value.TryGetProperty("events", out var events) && events.ValueKind == JsonValueKind.Array)
        {
            foreach (var ev in events.EnumerateArray())
            {
                switch (Member(ev, "kind"))
                {
                    case "installed":
                        Out("event installed");
                        break;
                    case "first_run":
                        Out("event first_run");
                        break;
                    case "updated":
                        Out($"event updated {Member(ev, "from")}");
                        break;
                }
            }
        }

        if (Member(startup, "action") == "exit")
        {
            Out("exit rolled-back");
            return 0;
        }

        // The tree's root: the nearest directory above this one that holds the update configuration
        // (at the root on Linux and Windows, under Contents/Resources in a macOS bundle).
        var tree = dir;
        while (tree is not null
               && !File.Exists(Path.Combine(tree, "lunepack-update.json"))
               && !File.Exists(Path.Combine(tree, "Contents", "Resources", "lunepack-update.json")))
        {
            tree = Path.GetDirectoryName(tree);
        }
        string? flagsFile = null;
        if (tree is not null)
        {
            var atRoot = Path.Combine(tree, "e2e-flags");
            var inBundle = Path.Combine(tree, "Contents", "Resources", "e2e-flags");
            if (File.Exists(atRoot))
            {
                flagsFile = atRoot;
            }
            else if (File.Exists(inBundle))
            {
                flagsFile = inBundle;
            }
        }

        var crash = false;
        var noConfirm = false;
        string? slow = null;
        string? hold = null;
        if (flagsFile is not null)
        {
            foreach (var line in File.ReadAllLines(flagsFile))
            {
                var space = line.IndexOf(' ');
                var word = space < 0 ? line : line[..space];
                var rest = space < 0 ? "" : line[(space + 1)..];
                switch (word)
                {
                    case "crash-on-start":
                        crash = true;
                        break;
                    case "exit-without-confirm":
                        noConfirm = true;
                        break;
                    case "slow-confirm":
                        slow = rest;
                        break;
                    case "hold":
                        hold = rest;
                        break;
                }
            }
        }
        var slowSecs = Seconds(slow);
        var holdSecs = Seconds(hold);

        if (crash)
        {
            Out("crash");
            Environment.Exit(3);
        }
        if (noConfirm)
        {
            Out("exit-without-confirm");
            return 0;
        }
        if (slowSecs is not null)
        {
            Out("slow-confirm");
            Sleep(slowSecs.Value);
        }

        Call(["confirm", "--json"]);
        switch (rc)
        {
            case 0:
                switch (Member(LastObject(), "outcome"))
                {
                    case "confirmed":
                        Out("confirmed");
                        break;
                    case "nothing_pending":
                        Out("nothing-pending");
                        break;
                    default:
                        Out("error confirm");
                        return 1;
                }
                break;
            case TokenMismatch:
                Out("error token-mismatch");
                return 1;
            default:
                Out("error confirm");
                return 1;
        }

        if (holdSecs is not null)
        {
            Out("hold");
            Sleep(holdSecs.Value);
        }

        if (!update)
        {
            return 0;
        }

        Call(["check", "--json"]);
        if (rc != 0)
        {
            Out("error check");
            return 1;
        }
        var check = LastObject();
        if (check is not null
            && check.Value.TryGetProperty("update", out var updateMember)
            && updateMember.ValueKind == JsonValueKind.Null)
        {
            Out("check none");
            return 0;
        }
        var found = check is not null
            && check.Value.TryGetProperty("update", out var updateObject)
            && updateObject.ValueKind == JsonValueKind.Object
                ? Member(updateObject, "version")
                : "";
        if (found.Length == 0)
        {
            Out("error check");
            return 1;
        }
        Out($"check {found}");

        Call(["download", "--json", "--expect-version", found]);
        var download = LastObject();
        var staged = download is not null
            && download.Value.TryGetProperty("staged", out var stagedMember)
            && stagedMember.ValueKind == JsonValueKind.True
                ? Member(download, "version")
                : "";
        if (rc != 0 || staged.Length == 0)
        {
            Out("error download");
            return 1;
        }
        Out($"staged {staged}");

        // The applier waits for this process by its own pid: the runtime's parent is this process
        // already, and naming it keeps the call the same as the shell app's (docs/RUNTIME.md).
        var apply = new List<string>
        {
            "apply-and-restart", "--json",
            "--wait-pid", Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "--expect-version", staged,
        };
        if (noUi)
        {
            apply.Add("--no-ui");
        }
        if (background)
        {
            apply.Add("--background");
        }
        apply.Add("--");
        apply.Add("--after-update");
        Call(apply);
        if (rc != 0)
        {
            Out("error apply");
            return 1;
        }
        Out("apply-scheduled");
        return 0;
    }

    // One line `<tree version> <outcome>` to the file LUNEPACK_E2E_OUT.
    public void Out(string outcome) => Append("LUNEPACK_E2E_OUT", outcome);

    private void Detail(string text) => Append("LUNEPACK_E2E_DETAIL", text);

    private void Append(string variable, string text)
    {
        var path = Environment.GetEnvironmentVariable(variable);
        if (string.IsNullOrEmpty(path))
        {
            return;
        }
        // One write in append mode, so the line is whole even when another process appends too.
        var bytes = Utf8.GetBytes($"{version} {text}\n");
        using var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
        stream.Write(bytes, 0, bytes.Length);
    }

    // Runs the runtime with the arguments and no shell. Sets rc (the exit code) and last (the final
    // non-empty line of stdout, the result or error object). The runtime's stderr stays ours.
    private void Call(IEnumerable<string> arguments)
    {
        var info = new ProcessStartInfo(runtime)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            StandardOutputEncoding = Utf8,
        };
        foreach (var argument in arguments)
        {
            info.ArgumentList.Add(argument);
        }
        using var process = Process.Start(info) ?? throw new InvalidOperationException("the runtime did not start");
        var text = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        rc = process.ExitCode;
        last = "";
        foreach (var line in text.Split('\n'))
        {
            var trimmed = line.TrimEnd('\r');
            if (trimmed.Length > 0)
            {
                last = trimmed;
            }
        }
    }

    // The last line as a JSON object, or null when it is none.
    private JsonElement? LastObject()
    {
        try
        {
            using var document = JsonDocument.Parse(last);
            return document.RootElement.ValueKind == JsonValueKind.Object ? document.RootElement.Clone() : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    // The value of a string member, empty when it is absent, null or not a string.
    private static string Member(JsonElement? element, string name)
    {
        if (element is { ValueKind: JsonValueKind.Object } o
            && o.TryGetProperty(name, out var value)
            && value.ValueKind == JsonValueKind.String)
        {
            return value.GetString() ?? "";
        }
        return "";
    }

    // The digits of a flag's argument, or null when the argument is not all digits.
    private static long? Seconds(string? text)
    {
        if (text is null || text.Length == 0 || !text.All(char.IsAsciiDigit))
        {
            return null;
        }
        return long.TryParse(text, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var value)
            ? value
            : null;
    }

    private static void Sleep(long seconds) =>
        Thread.Sleep((int)Math.Min(seconds * 1000, int.MaxValue));

    private static bool IsExecutable(string path)
    {
        if (!File.Exists(path))
        {
            return false;
        }
        if (OperatingSystem.IsWindows())
        {
            return true;
        }
        const UnixFileMode any = UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute;
        return (File.GetUnixFileMode(path) & any) != 0;
    }

    // The path with every link in it resolved, as `readlink -f` gives it (the shell app's own path).
    private static string RealPath(string path, int depth = 0)
    {
        var full = Path.GetFullPath(path);
        if (depth > 16)
        {
            return full;
        }
        var root = Path.GetPathRoot(full) ?? "";
        var current = root;
        foreach (var part in full[root.Length..].Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, part);
            FileSystemInfo info = Directory.Exists(current) ? new DirectoryInfo(current) : new FileInfo(current);
            var target = info.LinkTarget;
            if (target is null)
            {
                continue;
            }
            current = RealPath(Path.GetFullPath(target, Path.GetDirectoryName(current) ?? root), depth + 1);
        }
        return current;
    }
}
