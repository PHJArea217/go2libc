# go2libc

Use LD_PRELOAD libraries with Go applications (and many other applications that make direct syscalls)

# Background

Go applications make direct syscalls from the application's executable section, rather than routing them through libc, making them incompatible with LD_PRELOAD libraries.

* https://groups.google.com/g/golang-nuts/c/nPemezHF57s
* https://groups.google.com/g/golang-dev/c/zWV9KYYJkKI
* https://elixir.bootlin.com/linux/latest/source/samples/seccomp/bpf-direct.c

# Design

An LD_PRELOAD library is created to intercept all relevant system calls made in the Go application's executable section, determined in one of two ways:

* reading /proc/self/maps
* inserting two objects with symbols in the .text section before and after a .a file created by `go build -buildmode=c-archive`.

Then, a seccomp filter is installed in the LD\_PRELOAD library's constructor such that:
* deny all execve-like system calls (needed, because the exec'd application would inherit the seccomp filter)
* allow the syscall if instruction_pointer not in the main application's executable section (as determined above)
* otherwise `SECCOMP_RET_TRAP` if syscall is listed below:

bind, connect, listen, accept, openat

* otherwise, allow syscall

The SIGSYS handler would make the syscall itself, but through the libc wrapper function, in a way such that it can be intercepted with other LD_PRELOAD libraries.

# Limitations

* Must compile go app with `CGO_ENABLED=1`.
