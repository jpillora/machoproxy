# machoproxy

A Go launcher that logs calls made by a macOS Mach-O executable, then passes
them through to their original implementations. No sudo and no subprocess:
`exec` replaces the launcher with the target, keeping the same PID and parent.
A small embedded C dylib provides the hooks inside the target process.

```sh
make build
./machoproxy ./my-program arg1 "argument with spaces"
```

The default log is `./.log`, relative to the directory where you run
the command. Runs append to it. To choose another filename:

```sh
./machoproxy -o trace.log ./my-program arg1
```

Options stop at the executable; everything after it passes through unchanged,
including empty arguments and flags. Executables can also be resolved through
`PATH`. The target keeps the working directory, credentials, stdin, stdout,
stderr, and normal exit/signal behavior. Nothing routes arguments through a
shell. The executable is not modified or re-signed.

## What gets logged

Each call record contains a Unix timestamp with nanoseconds, PID, thread ID,
arguments, return value, and `errno` on failure. For example:

```text
1788854400.123456789 pid=1234 tid=5678 loaded backend=dyld-interpose coverage=library-calls
1788854400.123500000 pid=1234 tid=5678 open("data.txt", flags=0x0, mode=00) = 4 errno=0
1788854400.123600000 pid=1234 tid=5678 read(4, 0x12340000, 4096) = 128 errno=0
1788854400.123700000 pid=1234 tid=5678 close(4) = 0 errno=0
```

Hooks cover common file operations (`open`, `openat`, `read`, `write`, vector
and positioned I/O, metadata, rename, unlink, directories, descriptors), sockets
(`socket`, `bind`, `connect`, `listen`, `accept`, send/receive), memory mapping,
and process calls (`fork`, `execve`, `posix_spawn`, `kill`, `exit`). Selected
`$NOCANCEL` entry points are hooked too. The exact list is in
[`internal/hook/hook.c`](internal/hook/hook.c).

Paths are escaped and limited to 256 bytes; IPv4/IPv6 endpoints are decoded.
Buffer contents are not recorded. Ordinary calls are logged when they return;
exec/spawn/exit also log before calling through. The logger preserves `errno`,
guards against recursion, and writes each bounded record without stdio buffering.
Unreadable path pointers are logged as pointers, without dereferencing them.

## macOS limits

This is **library-call interception**, not a complete kernel syscall trace.
Direct `svc`/`syscall` instructions, Mach traps, unhooked symbols, some calls
internal to system libraries, and calls before the hook initializes are outside
its coverage. Go's usual macOS file I/O goes through libSystem and is tested.

Use an unrestricted development executable. SIP-protected system binaries
(such as `/bin/ls`), setuid/setgid programs, hardened apps with library
validation, or binaries with restricted dyld settings can strip or reject
`DYLD_INSERT_LIBRARIES`. The launcher rejects setuid/setgid and files carrying
the SIP restricted flag; other signing restrictions are enforced by dyld.
It does not disable SIP or change signing settings.

Look for `loaded backend=dyld-interpose` in the log to confirm injection. A
`launcher exec=...` line alone only confirms that the launcher ran. With no
supervisor process remaining after exec, it cannot report an injection failure
after the fact or record every termination (for example, SIGKILL).

Tracing introduces overhead and one open log descriptor. If the target closes
that descriptor, tracing stops. Child processes created by the **target itself**
can inherit the hooks and log descriptor; machoproxy creates none. Later execs
only remain traced if the target preserves the injection environment and dyld
allows it. New logs have mode `0600`; existing files retain their permissions.

## Build and test

Requires macOS, Go 1.24+, and Xcode Command Line Tools for rebuilding the dylib.

```sh
make build
make test
```

`go generate ./...` compiles a universal arm64/x86_64 dylib; `go build` embeds it
in the Go executable. The generated dylib is included, so `go build .` also
works without regenerating it. Rebuild it after changing the C source. The
launcher itself does not need cgo. At runtime the embedded dylib is extracted
to `~/Library/Caches/machoproxy/hook-<sha256>.dylib` and reused; there are no
runtime compiler or helper processes. Only the Go executable needs distributing.

Integration tests run real C and Go Mach-O targets without privileges. They
check PID/parent preservation, arguments, stdio, exit status, signals, file and
socket behavior, multithreaded logging, `errno`, invalid pointers, and log append
behavior. Both dylib architectures are built; execution tests use the host's
native architecture.
