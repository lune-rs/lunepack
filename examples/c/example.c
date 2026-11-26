/* The C example app: the same app as the .NET example (examples/dotnet/Program.cs) and the shell
 * app of the end-to-end suite, written against the C API (crates/lunepack-ffi/include/lunepack.h).
 *
 * At every start it calls lunepack_startup with its own arguments first and exits when the library
 * says so (a rollback); then it acts on the marker file `e2e-flags` at its tree's root
 * (crash-on-start, exit-without-confirm, slow-confirm <secs>, hold <secs>), confirms its health,
 * and with --update runs check, download, stage and apply-and-restart (with --no-ui as well, the
 * call carries LUNEPACK_APPLY_NO_UI: no update window). Outcomes go to the file LUNEPACK_E2E_OUT
 * as `<tree version> <outcome>`, the executable's real path to LUNEPACK_E2E_DETAIL (neither is
 * written when its variable is unset).
 *
 * `--selftest` needs no install: it checks the library against its header and exits 0 when all
 * holds.
 *
 * Plain C99 (it also compiles as C++), one file, no dependency but the C library, the header and
 * the minimum OS calls: the executable's own path, a sleep. No path ends in an abort (a crash dialog
 * on macOS): "crash on start" is exit(3).
 */

#define _XOPEN_SOURCE 700
#define _CRT_SECURE_NO_WARNINGS

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lunepack.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif
#endif

#define PATH_CAP 4096

static const char *g_version = "-";
static char g_version_buf[128];

/* One line `<tree version> <outcome>` to the file named by `variable`; one write, so the line is
 * whole even when another process appends too. */
static void append(const char *variable, const char *text)
{
    const char *path = getenv(variable);
    char line[PATH_CAP + 256];
    int n;
    FILE *f;
    if (path == NULL || path[0] == '\0') {
        return;
    }
    n = snprintf(line, sizeof line, "%s %s\n", g_version, text);
    if (n <= 0 || (size_t)n >= sizeof line) {
        return;
    }
    f = fopen(path, "ab");
    if (f == NULL) {
        return;
    }
    (void)fwrite(line, 1, (size_t)n, f);
    (void)fclose(f);
}

static void out(const char *outcome)
{
    append("LUNEPACK_E2E_OUT", outcome);
}

static void out2(const char *outcome, const char *argument)
{
    char line[512];
    (void)snprintf(line, sizeof line, "%s %s", outcome, argument);
    out(line);
}

/* The executable's own path, links resolved; 0 on failure. */
static int self_path(char *buf, size_t cap)
{
#ifdef _WIN32
    DWORD n = GetModuleFileNameA(NULL, buf, (DWORD)cap);
    return n > 0 && n < (DWORD)cap;
#elif defined(__APPLE__)
    char raw[PATH_CAP];
    uint32_t size = (uint32_t)sizeof raw;
    (void)cap; /* realpath fills `buf`, which holds at least PATH_MAX */
    if (_NSGetExecutablePath(raw, &size) != 0) {
        return 0;
    }
    return realpath(raw, buf) != NULL;
#else
    ssize_t n = readlink("/proc/self/exe", buf, cap - 1);
    if (n <= 0) {
        return 0;
    }
    buf[n] = '\0';
    return 1;
#endif
}

static void sleep_secs(unsigned long secs)
{
#ifdef _WIN32
    while (secs > 0) {
        unsigned long step = secs > 3600 ? 3600 : secs;
        Sleep((DWORD)(step * 1000));
        secs -= step;
    }
#else
    while (secs > 0) {
        unsigned int step = secs > 3600 ? 3600u : (unsigned int)secs;
        secs -= step;
        while (step > 0) {
            step = sleep(step);
        }
    }
#endif
}

static int file_exists(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return 0;
    }
    (void)fclose(f);
    return 1;
}

/* Cuts `path` back to its parent directory; 0 when there is none. */
static int to_parent(char *path)
{
    char *slash = strrchr(path, '/');
#ifdef _WIN32
    char *back = strrchr(path, '\\');
    if (back != NULL && (slash == NULL || back > slash)) {
        slash = back;
    }
#endif
    if (slash == NULL || slash == path) {
        return 0;
    }
    *slash = '\0';
    return 1;
}

/* The digits of a flag's argument, or -1 when the argument is not all digits. */
static long seconds_of(const char *text)
{
    long value = 0;
    size_t i;
    if (text[0] == '\0') {
        return -1;
    }
    for (i = 0; text[i] != '\0'; i++) {
        if (text[i] < '0' || text[i] > '9') {
            return -1;
        }
        if (value > (LONG_MAX - 9) / 10) {
            return -1;
        }
        value = value * 10 + (text[i] - '0');
    }
    return value;
}

typedef struct {
    int crash;
    int no_confirm;
    long slow;
    long hold;
} Flags;

/* Reads the marker file at the tree's root: the nearest directory above the executable's that holds
 * the update configuration (at the root on Linux and Windows, under Contents/Resources in a macOS
 * bundle). */
static Flags read_flags(const char *self)
{
    Flags flags;
    char tree[PATH_CAP];
    char probe[PATH_CAP + 64];
    char found[PATH_CAP + 64];
    int have = 0;
    flags.crash = 0;
    flags.no_confirm = 0;
    flags.slow = -1;
    flags.hold = -1;
    if (strlen(self) >= sizeof tree) {
        return flags;
    }
    strcpy(tree, self);
    while (to_parent(tree)) {
        (void)snprintf(probe, sizeof probe, "%s/lunepack-update.json", tree);
        if (file_exists(probe)) {
            (void)snprintf(found, sizeof found, "%s/e2e-flags", tree);
            have = file_exists(found);
            break;
        }
        (void)snprintf(probe, sizeof probe, "%s/Contents/Resources/lunepack-update.json", tree);
        if (file_exists(probe)) {
            (void)snprintf(found, sizeof found, "%s/e2e-flags", tree);
            if (file_exists(found)) {
                have = 1;
            } else {
                (void)snprintf(found, sizeof found, "%s/Contents/Resources/e2e-flags", tree);
                have = file_exists(found);
            }
            break;
        }
    }
    if (have) {
        FILE *f = fopen(found, "rb");
        char line[1024];
        if (f != NULL) {
            while (fgets(line, sizeof line, f) != NULL) {
                size_t n = strlen(line);
                char *space;
                const char *rest;
                while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) {
                    line[--n] = '\0';
                }
                space = strchr(line, ' ');
                if (space != NULL) {
                    *space = '\0';
                    rest = space + 1;
                } else {
                    rest = "";
                }
                if (strcmp(line, "crash-on-start") == 0) {
                    flags.crash = 1;
                } else if (strcmp(line, "exit-without-confirm") == 0) {
                    flags.no_confirm = 1;
                } else if (strcmp(line, "slow-confirm") == 0) {
                    flags.slow = seconds_of(rest);
                } else if (strcmp(line, "hold") == 0) {
                    flags.hold = seconds_of(rest);
                }
            }
            (void)fclose(f);
        }
    }
    return flags;
}

/* Prints `error <step>` and gives the exit code of a failed step. */
static int failed(const char *step)
{
    out2("error", step);
    return 1;
}

/* check, download, stage and apply-and-restart. */
static int run_update(int no_ui, int background)
{
    LunepackUpdater *updater = NULL;
    LunepackUpdateInfo *info = NULL;
    LunepackDownloaded *downloaded = NULL;
    LunepackStaged *staged = NULL;
    const char *restart[1];
    char found[128];
    char staged_version[128];
    const char *text;
    LunepackStatus status;
    unsigned int flags = 0;
    int code;

    status = lunepack_updater_open(NULL, &updater);
    if (status != LUNEPACK_STATUS_OK) {
        return failed("check");
    }
    status = lunepack_updater_check(updater, NULL, NULL, NULL, &info);
    if (status != LUNEPACK_STATUS_OK) {
        lunepack_updater_free(updater);
        return failed("check");
    }
    if (info == NULL) {
        out("check none");
        lunepack_updater_free(updater);
        return 0;
    }
    text = lunepack_update_info_version(info);
    if (text == NULL || strlen(text) >= sizeof found) {
        lunepack_update_info_free(info);
        lunepack_updater_free(updater);
        return failed("check");
    }
    strcpy(found, text);
    out2("check", found);

    status = lunepack_updater_download(updater, info, NULL, NULL, NULL, &downloaded);
    lunepack_update_info_free(info);
    if (status != LUNEPACK_STATUS_OK) {
        lunepack_updater_free(updater);
        return failed("download");
    }
    /* `stage` consumes the downloaded handle whatever the status. */
    status = lunepack_updater_stage(updater, downloaded, NULL, NULL, NULL, &staged);
    lunepack_updater_free(updater);
    text = status == LUNEPACK_STATUS_OK ? lunepack_staged_version(staged) : NULL;
    if (text == NULL || strlen(text) >= sizeof staged_version) {
        lunepack_staged_free(staged);
        return failed("stage");
    }
    strcpy(staged_version, text);
    lunepack_staged_free(staged);
    out2("staged", staged_version);

    if (no_ui) {
        flags |= LUNEPACK_APPLY_NO_UI;
    }
    if (background) {
        flags |= LUNEPACK_APPLY_BACKGROUND;
    }
    restart[0] = "--after-update";
    status = lunepack_apply_and_restart(staged_version, flags, restart, 1);
    if (status != LUNEPACK_STATUS_OK) {
        return failed("apply");
    }
    out("apply-scheduled");
    code = 0;
    return code;
}

static int run(int argc, char **argv)
{
    char self[PATH_CAP];
    LunepackStartup *startup = NULL;
    LunepackStatus status;
    Flags flags;
    int update = 0;
    int no_ui = 0;
    int background = 0;
    int i;
    size_t events;
    size_t e;
    uint32_t outcome = 0;

#ifdef _WIN32
    /* main's argv on Windows is in the ANSI code page, not UTF-8, which lunepack_startup requires
     * of an explicit list (a non-ASCII argument would be `usage`). (NULL, 0) makes the library
     * read the process's own arguments from the wide command line instead. */
    status = lunepack_startup(NULL, 0, &startup);
#else
    status = lunepack_startup(argc > 1 ? (const char *const *)(argv + 1) : NULL,
                              argc > 1 ? (size_t)(argc - 1) : 0, &startup);
#endif
    if (status != LUNEPACK_STATUS_OK) {
        return failed("startup");
    }
    {
        const char *tree = lunepack_startup_tree_version(startup);
        if (tree != NULL && strlen(tree) < sizeof g_version_buf) {
            strcpy(g_version_buf, tree);
            g_version = g_version_buf;
        }
    }
    if (self_path(self, sizeof self)) {
        char detail[PATH_CAP + 8];
        (void)snprintf(detail, sizeof detail, "exe %s", self);
        append("LUNEPACK_E2E_DETAIL", detail);
    } else {
        self[0] = '\0';
    }
    out("start");

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--after-update") == 0) {
            out("arg after-update");
        } else if (strcmp(argv[i], "--update") == 0) {
            update = 1;
        } else if (strcmp(argv[i], "--no-ui") == 0) {
            no_ui = 1;
        } else if (strcmp(argv[i], "--background") == 0) {
            background = 1;
        }
    }

    /* The events, oldest first. */
    events = lunepack_startup_event_count(startup);
    for (e = 0; e < events; e++) {
        switch (lunepack_startup_event_kind(startup, e)) {
        case LUNEPACK_EVENT_INSTALLED:
            out("event installed");
            break;
        case LUNEPACK_EVENT_FIRST_RUN:
            out("event first_run");
            break;
        case LUNEPACK_EVENT_UPDATED: {
            const char *from = lunepack_startup_event_from(startup, e);
            out2("event updated", from != NULL ? from : "");
            break;
        }
        default:
            break;
        }
    }

    if (lunepack_startup_should_exit(startup)) {
        out("exit rolled-back");
        lunepack_startup_free(startup);
        return 0;
    }
    lunepack_startup_free(startup);

    flags = read_flags(self);
    if (flags.crash) {
        out("crash");
        exit(3);
    }
    if (flags.no_confirm) {
        out("exit-without-confirm");
        return 0;
    }
    if (flags.slow >= 0) {
        out("slow-confirm");
        sleep_secs((unsigned long)flags.slow);
    }

    status = lunepack_confirm_healthy(&outcome);
    if (status == LUNEPACK_STATUS_OK) {
        if (outcome == LUNEPACK_CONFIRM_CONFIRMED) {
            out("confirmed");
        } else if (outcome == LUNEPACK_CONFIRM_NOTHING_PENDING) {
            out("nothing-pending");
        } else {
            return failed("confirm");
        }
    } else if (status == LUNEPACK_STATUS_TOKEN_MISMATCH) {
        out("error token-mismatch");
        return 1;
    } else {
        return failed("confirm");
    }

    if (flags.hold >= 0) {
        out("hold");
        sleep_secs((unsigned long)flags.hold);
    }
    if (!update) {
        return 0;
    }
    return run_update(no_ui, background);
}

/* ---- --selftest ------------------------------------------------------------------------------- */

static int g_failures;

static void check_that(int ok, const char *what)
{
    if (!ok) {
        (void)fprintf(stderr, "selftest: FAILED: %s\n", what);
        g_failures++;
    }
}

static int same(const char *a, const char *b)
{
    return a != NULL && b != NULL && strcmp(a, b) == 0;
}

static int selftest(void)
{
    LunepackCancelToken *token;
    LunepackUpdater *updater = (LunepackUpdater *)0x10;
    LunepackUpdateInfo *info = (LunepackUpdateInfo *)0x10;
    LunepackStartup *startup = (LunepackStartup *)0x10;
    uint32_t outcome = 7;

    check_that(lunepack_abi_version() == LUNEPACK_ABI_VERSION, "abi version equals the header's");
    check_that(lunepack_library_version() != NULL && lunepack_library_version()[0] != '\0',
               "library version is text");
    check_that(same(lunepack_status_name(LUNEPACK_STATUS_OK), "ok"), "status 0 is ok");
    check_that(same(lunepack_status_name(LUNEPACK_STATUS_USAGE), "usage"), "status usage");
    check_that(same(lunepack_status_name(LUNEPACK_STATUS_UPDATE_CONFIG), "update_config"),
               "status update_config");
    check_that(same(lunepack_status_name(LUNEPACK_STATUS_INTERNAL), "internal"), "status internal");
    check_that(lunepack_status_name(1) == NULL, "an unknown status has no name");
    check_that(same(lunepack_phase_name(LUNEPACK_PHASE_DOWNLOAD), "download"), "phase name");
    check_that(lunepack_phase_name(LUNEPACK_PHASE_UNKNOWN) == NULL, "unknown phase has no name");
    check_that(same(lunepack_source_name(LUNEPACK_SOURCE_FULL_PACK), "full_pack"), "source name");

    token = lunepack_cancel_token_new();
    check_that(token != NULL, "a cancel token is made");
    check_that(!lunepack_cancel_token_is_cancelled(token), "a new token is not cancelled");
    lunepack_cancel_token_cancel(token);
    check_that(lunepack_cancel_token_is_cancelled(token), "a cancelled token says so");
    lunepack_cancel_token_free(token);
    lunepack_cancel_token_free(NULL);
    check_that(!lunepack_cancel_token_is_cancelled(NULL), "NULL is not cancelled");

    /* Outside an install there is no update configuration. */
    check_that(lunepack_updater_open(NULL, &updater) == LUNEPACK_STATUS_UPDATE_CONFIG,
               "open outside an install is update_config");
    check_that(updater == NULL, "a failed open leaves NULL");
    check_that(lunepack_updater_open("Bad Channel", &updater) == LUNEPACK_STATUS_USAGE,
               "a channel that is not an id is usage");
    check_that(lunepack_updater_open(NULL, NULL) == LUNEPACK_STATUS_USAGE, "a NULL out is usage");

    check_that(lunepack_updater_check(NULL, NULL, NULL, NULL, &info) == LUNEPACK_STATUS_USAGE,
               "check without an updater is usage");
    check_that(info == NULL, "a refused check leaves NULL");
    check_that(lunepack_update_info_version(NULL) == NULL, "NULL info has no version");
    check_that(lunepack_update_info_download_size_max(NULL) == 0, "NULL info has no size");
    check_that(!lunepack_update_info_time_checked(NULL), "NULL info is not time-checked");
    check_that(lunepack_staged_version(NULL) == NULL, "NULL staged has no version");
    lunepack_update_info_free(NULL);
    lunepack_downloaded_free(NULL);
    lunepack_staged_free(NULL);
    lunepack_updater_free(NULL);

    check_that(lunepack_startup(NULL, 2, &startup) == LUNEPACK_STATUS_USAGE,
               "startup with arguments but no vector is usage");
    check_that(startup == NULL, "a refused startup leaves NULL");
    check_that(lunepack_startup(NULL, 0, &startup) == LUNEPACK_STATUS_UPDATE_CONFIG,
               "startup outside an install is update_config");
    check_that(lunepack_startup_event_count(NULL) == 0, "NULL startup has no events");
    check_that(!lunepack_startup_should_exit(NULL), "NULL startup does not exit");
    lunepack_startup_free(NULL);

    check_that(lunepack_confirm_healthy(NULL) == LUNEPACK_STATUS_USAGE, "confirm needs an out");
    check_that(lunepack_confirm_healthy(&outcome) == LUNEPACK_STATUS_UPDATE_CONFIG,
               "confirm outside an install is update_config");
    check_that(outcome == 0, "a failed confirm clears its outcome");
    check_that(lunepack_apply_and_restart("1.0", 0, NULL, 0) == LUNEPACK_STATUS_USAGE,
               "a version that is not canonical is usage");
    check_that(lunepack_apply_and_restart(NULL, 4, NULL, 0) == LUNEPACK_STATUS_USAGE,
               "an unknown flag bit is usage");
    check_that(lunepack_apply_and_restart(NULL, 0, NULL, 0) == LUNEPACK_STATUS_UPDATE_CONFIG,
               "apply outside an install is update_config");

    if (g_failures != 0) {
        (void)fprintf(stderr, "selftest: %d check(s) failed\n", g_failures);
        return 1;
    }
    (void)printf("selftest ok\n");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--selftest") == 0) {
        return selftest();
    }
    return run(argc, argv);
}
