#pragma once
#include <sys/types.h>
#include <stddef.h>
#include <stdint.h>

// Process primitives shared by the privileged helper and the local checks.
// No authorization API, shell, or PATH lookup is used here.

/// Starts VPNSupervisor with: stdin/stdout/stderr = one end of a new socket pair
/// (the STOP/EOF control channel and the output stream), fd 3 = config_fd and,
/// when cookie_fd >= 0, fd 4 = cookie_fd. Every other descriptor is closed
/// (POSIX_SPAWN_CLOEXEC_DEFAULT), signals are reset, the environment is exactly
/// `environment`, and the supervisor gets its own process group so that a job
/// manager cleaning the parent's group cannot SIGKILL a tunnel mid-cleanup.
/// `arguments` is NULL terminated and includes argv[0].
/// Returns the parent's end of the socket pair (close-on-exec) or -1 with errno.
int vpn_spawn_supervisor(const char *supervisor, char *const arguments[], char *const environment[],
                         int config_fd, int cookie_fd, pid_t *pid);

/// Runs a short, non-network probe such as `--help`. When uid/gid are not
/// (uid_t)-1/(gid_t)-1 and the caller is root, the child drops to that identity
/// before exec. Output (stdout+stderr) is captured up to `capacity` bytes; the
/// child receives SIGTERM after `timeout_ms` and SIGKILL one second later.
/// Returns 0 when the child was reaped (status in *status), -1 otherwise.
int vpn_run_probe(const char *path, char *const arguments[], char *const environment[],
                  uid_t uid, gid_t gid, int timeout_ms,
                  char *output, size_t capacity, size_t *length, int *status);

/// Start time of a live process, used to tell a PID from a reused one.
/// Returns 0 on success, -1 if the process does not exist or cannot be read.
int vpn_process_start_time(pid_t pid, uint64_t *seconds, uint64_t *microseconds);

/// Local checks only: input 0 chooses an ephemeral loopback port; a positive input
/// probes that exact port with the client's SO_REUSEADDR semantics.
int vpn_reserve_port(int *port);

/// 1 when this process runs inside a Seatbelt sandbox (for example Homebrew's
/// sandbox-exec profile for cask steps), 0 otherwise. Read-only system query.
int vpn_is_sandboxed(void);
