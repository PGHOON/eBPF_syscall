#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "syscall_trace_all.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} output SEC(".maps");

struct kernel_tracepoints {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    long syscall_nr;
    void *filename_ptr;
    long argv_ptr;
    long envp_ptr;
};

#define TRACE_SYSCALL(syscall_name, tp_name) \
SEC("tracepoint/syscalls/" #syscall_name) \
int trace_##syscall_name(struct kernel_tracepoints *ctx) { \
    struct data_t data = {}; \
    data.pid = bpf_get_current_pid_tgid() >> 32; \
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF; \
    bpf_get_current_comm(&data.command, sizeof(data.command)); \
    bpf_probe_read_kernel(&data.syscall, sizeof(data.syscall), tp_name); \
    bpf_probe_read_kernel_str(&data.container_id, sizeof(data.container_id), "/proc/self/cgroup"); \
    if (data.uid >= 0) { \
        bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data)); \
    } \
    return 0; \
}

TRACE_SYSCALL(sys_enter_accept, "accept")
TRACE_SYSCALL(sys_enter_accept4, "accept4")
TRACE_SYSCALL(sys_enter_access, "access")
TRACE_SYSCALL(sys_enter_acct, "acct")
TRACE_SYSCALL(sys_enter_add_key, "add_key")
TRACE_SYSCALL(sys_enter_adjtimex, "adjtimex")
TRACE_SYSCALL(sys_enter_alarm, "alarm")
TRACE_SYSCALL(sys_enter_arch_prctl, "arch_prctl")
TRACE_SYSCALL(sys_enter_bind, "bind")
TRACE_SYSCALL(sys_enter_bpf, "bpf")
TRACE_SYSCALL(sys_enter_brk, "brk")
TRACE_SYSCALL(sys_enter_capget, "capget")
TRACE_SYSCALL(sys_enter_capset, "capset")
TRACE_SYSCALL(sys_enter_chdir, "chdir")
TRACE_SYSCALL(sys_enter_chmod, "chmod")
TRACE_SYSCALL(sys_enter_chown, "chown")
TRACE_SYSCALL(sys_enter_chroot, "chroot")
TRACE_SYSCALL(sys_enter_clock_adjtime, "clock_adjtime")
TRACE_SYSCALL(sys_enter_clock_getres, "clock_getres") // 추가된 항목
TRACE_SYSCALL(sys_enter_clock_gettime, "clock_gettime")
TRACE_SYSCALL(sys_enter_clock_nanosleep, "clock_nanosleep")
TRACE_SYSCALL(sys_enter_clone, "clone")
TRACE_SYSCALL(sys_enter_close, "close")
TRACE_SYSCALL(sys_enter_connect, "connect")
TRACE_SYSCALL(sys_enter_creat, "creat")
TRACE_SYSCALL(sys_enter_delete_module, "delete_module")
TRACE_SYSCALL(sys_enter_dup, "dup")
TRACE_SYSCALL(sys_enter_dup2, "dup2")
TRACE_SYSCALL(sys_enter_dup3, "dup3")
TRACE_SYSCALL(sys_enter_epoll_create, "epoll_create")
TRACE_SYSCALL(sys_enter_epoll_create1, "epoll_create1")
TRACE_SYSCALL(sys_enter_epoll_ctl, "epoll_ctl")
TRACE_SYSCALL(sys_enter_epoll_pwait, "epoll_pwait")
TRACE_SYSCALL(sys_enter_epoll_wait, "epoll_wait")
TRACE_SYSCALL(sys_enter_eventfd, "eventfd")
TRACE_SYSCALL(sys_enter_eventfd2, "eventfd2")
TRACE_SYSCALL(sys_enter_execve, "execve")
TRACE_SYSCALL(sys_enter_execveat, "execveat")
TRACE_SYSCALL(sys_enter_exit, "exit")
TRACE_SYSCALL(sys_enter_exit_group, "exit_group")
TRACE_SYSCALL(sys_enter_faccessat, "faccessat")
TRACE_SYSCALL(sys_enter_faccessat2, "faccessat2") // 추가된 항목
TRACE_SYSCALL(sys_enter_fadvise64, "fadvise64")
TRACE_SYSCALL(sys_enter_fallocate, "fallocate")
TRACE_SYSCALL(sys_enter_fanotify_init, "fanotify_init")
TRACE_SYSCALL(sys_enter_fanotify_mark, "fanotify_mark")
TRACE_SYSCALL(sys_enter_fchdir, "fchdir")
TRACE_SYSCALL(sys_enter_fchmod, "fchmod")
TRACE_SYSCALL(sys_enter_fchmodat, "fchmodat")
TRACE_SYSCALL(sys_enter_fchown, "fchown")
TRACE_SYSCALL(sys_enter_fchownat, "fchownat")
TRACE_SYSCALL(sys_enter_fcntl, "fcntl")
TRACE_SYSCALL(sys_enter_fdatasync, "fdatasync")
TRACE_SYSCALL(sys_enter_fgetxattr, "fgetxattr")
TRACE_SYSCALL(sys_enter_finit_module, "finit_module")
TRACE_SYSCALL(sys_enter_flistxattr, "flistxattr")
TRACE_SYSCALL(sys_enter_flock, "flock")
TRACE_SYSCALL(sys_enter_fork, "fork")
TRACE_SYSCALL(sys_enter_fremovexattr, "fremovexattr")
TRACE_SYSCALL(sys_enter_fsetxattr, "fsetxattr")
//TRACE_SYSCALL(sys_enter_fstat, "fstat")
TRACE_SYSCALL(sys_enter_fstatfs, "fstatfs")
TRACE_SYSCALL(sys_enter_fsync, "fsync")
TRACE_SYSCALL(sys_enter_ftruncate, "ftruncate")
TRACE_SYSCALL(sys_enter_futex, "futex")
TRACE_SYSCALL(sys_enter_futimesat, "futimesat")
TRACE_SYSCALL(sys_enter_get_mempolicy, "get_mempolicy")
TRACE_SYSCALL(sys_enter_get_robust_list, "get_robust_list")
TRACE_SYSCALL(sys_enter_getcpu, "getcpu")
TRACE_SYSCALL(sys_enter_getcwd, "getcwd")
TRACE_SYSCALL(sys_enter_getdents, "getdents")
TRACE_SYSCALL(sys_enter_getdents64, "getdents64")
TRACE_SYSCALL(sys_enter_getegid, "getegid")
TRACE_SYSCALL(sys_enter_geteuid, "geteuid")
TRACE_SYSCALL(sys_enter_getgid, "getgid")
TRACE_SYSCALL(sys_enter_getgroups, "getgroups")
TRACE_SYSCALL(sys_enter_getitimer, "getitimer")
TRACE_SYSCALL(sys_enter_getpeername, "getpeername")
TRACE_SYSCALL(sys_enter_getpgid, "getpgid")
TRACE_SYSCALL(sys_enter_getpgrp, "getpgrp")
TRACE_SYSCALL(sys_enter_getpid, "getpid")
TRACE_SYSCALL(sys_enter_getppid, "getppid")
TRACE_SYSCALL(sys_enter_getpriority, "getpriority")
TRACE_SYSCALL(sys_enter_getrandom, "getrandom")
TRACE_SYSCALL(sys_enter_getresgid, "getresgid")
TRACE_SYSCALL(sys_enter_getresuid, "getresuid")
TRACE_SYSCALL(sys_enter_getrlimit, "getrlimit")
TRACE_SYSCALL(sys_enter_getrusage, "getrusage")
TRACE_SYSCALL(sys_enter_getsid, "getsid")
TRACE_SYSCALL(sys_enter_getsockname, "getsockname")
TRACE_SYSCALL(sys_enter_getsockopt, "getsockopt")
TRACE_SYSCALL(sys_enter_gettid, "gettid")
TRACE_SYSCALL(sys_enter_gettimeofday, "gettimeofday")
TRACE_SYSCALL(sys_enter_getuid, "getuid")
TRACE_SYSCALL(sys_enter_getxattr, "getxattr")
TRACE_SYSCALL(sys_enter_init_module, "init_module")
TRACE_SYSCALL(sys_enter_inotify_add_watch, "inotify_add_watch")
TRACE_SYSCALL(sys_enter_inotify_init, "inotify_init")
TRACE_SYSCALL(sys_enter_inotify_init1, "inotify_init1")
TRACE_SYSCALL(sys_enter_inotify_rm_watch, "inotify_rm_watch")
TRACE_SYSCALL(sys_enter_io_cancel, "io_cancel")
TRACE_SYSCALL(sys_enter_io_destroy, "io_destroy")
TRACE_SYSCALL(sys_enter_io_getevents, "io_getevents")
TRACE_SYSCALL(sys_enter_io_setup, "io_setup")
TRACE_SYSCALL(sys_enter_io_submit, "io_submit")
TRACE_SYSCALL(sys_enter_ioctl, "ioctl")
TRACE_SYSCALL(sys_enter_ioprio_get, "ioprio_get")
TRACE_SYSCALL(sys_enter_ioprio_set, "ioprio_set")
TRACE_SYSCALL(sys_enter_kcmp, "kcmp")
TRACE_SYSCALL(sys_enter_kexec_file_load, "kexec_file_load")
TRACE_SYSCALL(sys_enter_kexec_load, "kexec_load")
TRACE_SYSCALL(sys_enter_keyctl, "keyctl")
TRACE_SYSCALL(sys_enter_kill, "kill")
TRACE_SYSCALL(sys_enter_lchown, "lchown")
TRACE_SYSCALL(sys_enter_lgetxattr, "lgetxattr")
TRACE_SYSCALL(sys_enter_link, "link")
TRACE_SYSCALL(sys_enter_linkat, "linkat")
TRACE_SYSCALL(sys_enter_listen, "listen")
TRACE_SYSCALL(sys_enter_listxattr, "listxattr")
TRACE_SYSCALL(sys_enter_llistxattr, "llistxattr")
//TRACE_SYSCALL(sys_enter_lookup_dcookie, "lookup_dcookie")
TRACE_SYSCALL(sys_enter_lremovexattr, "lremovexattr")
TRACE_SYSCALL(sys_enter_lseek, "lseek")
TRACE_SYSCALL(sys_enter_lsetxattr, "lsetxattr")
TRACE_SYSCALL(sys_enter_madvise, "madvise")
TRACE_SYSCALL(sys_enter_mbind, "mbind")
TRACE_SYSCALL(sys_enter_migrate_pages, "migrate_pages")
TRACE_SYSCALL(sys_enter_mincore, "mincore")
TRACE_SYSCALL(sys_enter_mkdir, "mkdir")
TRACE_SYSCALL(sys_enter_mkdirat, "mkdirat")
TRACE_SYSCALL(sys_enter_mknod, "mknod")
TRACE_SYSCALL(sys_enter_mknodat, "mknodat")
TRACE_SYSCALL(sys_enter_mlock, "mlock")
TRACE_SYSCALL(sys_enter_mlock2, "mlock2")
TRACE_SYSCALL(sys_enter_mlockall, "mlockall")
TRACE_SYSCALL(sys_enter_mmap, "mmap")
TRACE_SYSCALL(sys_enter_modify_ldt, "modify_ldt")
TRACE_SYSCALL(sys_enter_mount, "mount")
TRACE_SYSCALL(sys_enter_move_pages, "move_pages")
TRACE_SYSCALL(sys_enter_mprotect, "mprotect")
TRACE_SYSCALL(sys_enter_mq_getsetattr, "mq_getsetattr")
TRACE_SYSCALL(sys_enter_mq_notify, "mq_notify")
TRACE_SYSCALL(sys_enter_mq_open, "mq_open")
TRACE_SYSCALL(sys_enter_mq_timedreceive, "mq_timedreceive")
TRACE_SYSCALL(sys_enter_mq_timedsend, "mq_timedsend")
TRACE_SYSCALL(sys_enter_mq_unlink, "mq_unlink")
TRACE_SYSCALL(sys_enter_mremap, "mremap")
TRACE_SYSCALL(sys_enter_msgctl, "msgctl")
TRACE_SYSCALL(sys_enter_msgget, "msgget")
TRACE_SYSCALL(sys_enter_msgrcv, "msgrcv")
TRACE_SYSCALL(sys_enter_msgsnd, "msgsnd")
TRACE_SYSCALL(sys_enter_msync, "msync")
TRACE_SYSCALL(sys_enter_munlock, "munlock")
TRACE_SYSCALL(sys_enter_munlockall, "munlockall")
TRACE_SYSCALL(sys_enter_munmap, "munmap")
TRACE_SYSCALL(sys_enter_name_to_handle_at, "name_to_handle_at")
TRACE_SYSCALL(sys_enter_nanosleep, "nanosleep")
TRACE_SYSCALL(sys_enter_newfstatat, "newfstatat")
//TRACE_SYSCALL(sys_enter_nfsservctl, "nfsservctl")
TRACE_SYSCALL(sys_enter_open, "open")
TRACE_SYSCALL(sys_enter_open_by_handle_at, "open_by_handle_at")
TRACE_SYSCALL(sys_enter_openat, "openat")
TRACE_SYSCALL(sys_enter_pause, "pause")
TRACE_SYSCALL(sys_enter_perf_event_open, "perf_event_open") // 추가된 항목
TRACE_SYSCALL(sys_enter_personality, "personality")
TRACE_SYSCALL(sys_enter_pidfd_send_signal, "pidfd_send_signal")
TRACE_SYSCALL(sys_enter_pidfd_getfd, "pidfd_getfd") // 추가된 항목
TRACE_SYSCALL(sys_enter_pipe, "pipe")
TRACE_SYSCALL(sys_enter_pipe2, "pipe2")
TRACE_SYSCALL(sys_enter_pivot_root, "pivot_root")
TRACE_SYSCALL(sys_enter_pkey_alloc, "pkey_alloc") // 추가된 항목
TRACE_SYSCALL(sys_enter_pkey_free, "pkey_free") // 추가된 항목
TRACE_SYSCALL(sys_enter_pkey_mprotect, "pkey_mprotect") // 추가된 항목
TRACE_SYSCALL(sys_enter_poll, "poll")
TRACE_SYSCALL(sys_enter_ppoll, "ppoll")
TRACE_SYSCALL(sys_enter_prctl, "prctl")
TRACE_SYSCALL(sys_enter_pread64, "pread64")
TRACE_SYSCALL(sys_enter_preadv, "preadv")
TRACE_SYSCALL(sys_enter_preadv2, "preadv2")
TRACE_SYSCALL(sys_enter_prlimit64, "prlimit64")
TRACE_SYSCALL(sys_enter_process_vm_readv, "process_vm_readv")
TRACE_SYSCALL(sys_enter_process_vm_writev, "process_vm_writev")
TRACE_SYSCALL(sys_enter_process_madvise, "process_madvise") // 추가된 항목
TRACE_SYSCALL(sys_enter_process_mrelease, "process_mrelease") // 추가된 항목
TRACE_SYSCALL(sys_enter_pselect6, "pselect6")
TRACE_SYSCALL(sys_enter_ptrace, "ptrace")
TRACE_SYSCALL(sys_enter_pwrite64, "pwrite64")
TRACE_SYSCALL(sys_enter_pwritev, "pwritev")
TRACE_SYSCALL(sys_enter_pwritev2, "pwritev2")
TRACE_SYSCALL(sys_enter_quotactl, "quotactl")
TRACE_SYSCALL(sys_enter_quotactl_fd, "quotactl_fd") // 추가된 항목
TRACE_SYSCALL(sys_enter_read, "read")
TRACE_SYSCALL(sys_enter_readahead, "readahead")
TRACE_SYSCALL(sys_enter_readlink, "readlink")
TRACE_SYSCALL(sys_enter_readlinkat, "readlinkat")
TRACE_SYSCALL(sys_enter_readv, "readv")
TRACE_SYSCALL(sys_enter_reboot, "reboot")
TRACE_SYSCALL(sys_enter_recvfrom, "recvfrom")
TRACE_SYSCALL(sys_enter_recvmmsg, "recvmmsg")
TRACE_SYSCALL(sys_enter_recvmsg, "recvmsg")
TRACE_SYSCALL(sys_enter_remap_file_pages, "remap_file_pages")
TRACE_SYSCALL(sys_enter_removexattr, "removexattr")
TRACE_SYSCALL(sys_enter_rename, "rename")
TRACE_SYSCALL(sys_enter_renameat, "renameat")
TRACE_SYSCALL(sys_enter_renameat2, "renameat2")
TRACE_SYSCALL(sys_enter_request_key, "request_key")
TRACE_SYSCALL(sys_enter_restart_syscall, "restart_syscall")
TRACE_SYSCALL(sys_enter_rmdir, "rmdir")
TRACE_SYSCALL(sys_enter_rt_sigaction, "rt_sigaction")
TRACE_SYSCALL(sys_enter_rt_sigpending, "rt_sigpending")
TRACE_SYSCALL(sys_enter_rt_sigprocmask, "rt_sigprocmask")
TRACE_SYSCALL(sys_enter_rt_sigqueueinfo, "rt_sigqueueinfo")
TRACE_SYSCALL(sys_enter_rt_sigreturn, "rt_sigreturn")
TRACE_SYSCALL(sys_enter_rt_sigsuspend, "rt_sigsuspend")
TRACE_SYSCALL(sys_enter_rt_sigtimedwait, "rt_sigtimedwait")
TRACE_SYSCALL(sys_enter_rt_tgsigqueueinfo, "rt_tgsigqueueinfo")
TRACE_SYSCALL(sys_enter_sched_get_priority_max, "sched_get_priority_max")
TRACE_SYSCALL(sys_enter_sched_get_priority_min, "sched_get_priority_min")
TRACE_SYSCALL(sys_enter_sched_getaffinity, "sched_getaffinity")
TRACE_SYSCALL(sys_enter_sched_getattr, "sched_getattr")
TRACE_SYSCALL(sys_enter_sched_getparam, "sched_getparam")
TRACE_SYSCALL(sys_enter_sched_getscheduler, "sched_getscheduler")
TRACE_SYSCALL(sys_enter_sched_rr_get_interval, "sched_rr_get_interval")
TRACE_SYSCALL(sys_enter_sched_setaffinity, "sched_setaffinity")
TRACE_SYSCALL(sys_enter_sched_setattr, "sched_setattr")
TRACE_SYSCALL(sys_enter_sched_setparam, "sched_setparam")
TRACE_SYSCALL(sys_enter_sched_setscheduler, "sched_setscheduler")
TRACE_SYSCALL(sys_enter_sched_yield, "sched_yield")
TRACE_SYSCALL(sys_enter_seccomp, "seccomp")
TRACE_SYSCALL(sys_enter_select, "select")
TRACE_SYSCALL(sys_enter_semctl, "semctl")
TRACE_SYSCALL(sys_enter_semget, "semget")
TRACE_SYSCALL(sys_enter_semop, "semop")
TRACE_SYSCALL(sys_enter_semtimedop, "semtimedop")
//TRACE_SYSCALL(sys_enter_sendfile, "sendfile")
TRACE_SYSCALL(sys_enter_sendmmsg, "sendmmsg")
TRACE_SYSCALL(sys_enter_sendmsg, "sendmsg")
TRACE_SYSCALL(sys_enter_sendto, "sendto")
TRACE_SYSCALL(sys_enter_set_mempolicy, "set_mempolicy")
TRACE_SYSCALL(sys_enter_set_robust_list, "set_robust_list")
TRACE_SYSCALL(sys_enter_set_tid_address, "set_tid_address")
TRACE_SYSCALL(sys_enter_setdomainname, "setdomainname")
TRACE_SYSCALL(sys_enter_setfsgid, "setfsgid")
TRACE_SYSCALL(sys_enter_setfsuid, "setfsuid")
TRACE_SYSCALL(sys_enter_setgid, "setgid")
TRACE_SYSCALL(sys_enter_setgroups, "setgroups")
TRACE_SYSCALL(sys_enter_sethostname, "sethostname")
TRACE_SYSCALL(sys_enter_setitimer, "setitimer")
TRACE_SYSCALL(sys_enter_setns, "setns")
TRACE_SYSCALL(sys_enter_setpgid, "setpgid")
TRACE_SYSCALL(sys_enter_setpriority, "setpriority")
TRACE_SYSCALL(sys_enter_setregid, "setregid")
TRACE_SYSCALL(sys_enter_setresgid, "setresgid")
TRACE_SYSCALL(sys_enter_setresuid, "setresuid")
TRACE_SYSCALL(sys_enter_setreuid, "setreuid")
TRACE_SYSCALL(sys_enter_setrlimit, "setrlimit")
TRACE_SYSCALL(sys_enter_setsid, "setsid")
TRACE_SYSCALL(sys_enter_setsockopt, "setsockopt")
TRACE_SYSCALL(sys_enter_settimeofday, "settimeofday")
TRACE_SYSCALL(sys_enter_setuid, "setuid")
TRACE_SYSCALL(sys_enter_setxattr, "setxattr")
TRACE_SYSCALL(sys_enter_shmat, "shmat")
TRACE_SYSCALL(sys_enter_shmctl, "shmctl")
TRACE_SYSCALL(sys_enter_shmdt, "shmdt")
TRACE_SYSCALL(sys_enter_shmget, "shmget")
TRACE_SYSCALL(sys_enter_shutdown, "shutdown")
TRACE_SYSCALL(sys_enter_sigaltstack, "sigaltstack")
TRACE_SYSCALL(sys_enter_signalfd, "signalfd")
TRACE_SYSCALL(sys_enter_signalfd4, "signalfd4")
TRACE_SYSCALL(sys_enter_socket, "socket")
TRACE_SYSCALL(sys_enter_socketpair, "socketpair")
TRACE_SYSCALL(sys_enter_splice, "splice")
//TRACE_SYSCALL(sys_enter_stat, "stat")
TRACE_SYSCALL(sys_enter_statfs, "statfs")
TRACE_SYSCALL(sys_enter_swapoff, "swapoff")
TRACE_SYSCALL(sys_enter_swapon, "swapon")
TRACE_SYSCALL(sys_enter_symlink, "symlink")
TRACE_SYSCALL(sys_enter_symlinkat, "symlinkat")
TRACE_SYSCALL(sys_enter_sync, "sync")
TRACE_SYSCALL(sys_enter_sync_file_range, "sync_file_range")
TRACE_SYSCALL(sys_enter_syncfs, "syncfs")
TRACE_SYSCALL(sys_enter_sysfs, "sysfs")
TRACE_SYSCALL(sys_enter_sysinfo, "sysinfo")
TRACE_SYSCALL(sys_enter_syslog, "syslog")
TRACE_SYSCALL(sys_enter_tee, "tee")
TRACE_SYSCALL(sys_enter_tgkill, "tgkill")
TRACE_SYSCALL(sys_enter_time, "time")
TRACE_SYSCALL(sys_enter_timer_create, "timer_create")
TRACE_SYSCALL(sys_enter_timer_delete, "timer_delete")
TRACE_SYSCALL(sys_enter_timer_getoverrun, "timer_getoverrun")
TRACE_SYSCALL(sys_enter_timer_gettime, "timer_gettime")
TRACE_SYSCALL(sys_enter_timer_settime, "timer_settime")
TRACE_SYSCALL(sys_enter_timerfd_create, "timerfd_create")
TRACE_SYSCALL(sys_enter_timerfd_gettime, "timerfd_gettime")
TRACE_SYSCALL(sys_enter_timerfd_settime, "timerfd_settime")
TRACE_SYSCALL(sys_enter_times, "times")
TRACE_SYSCALL(sys_enter_tkill, "tkill")
TRACE_SYSCALL(sys_enter_truncate, "truncate")
TRACE_SYSCALL(sys_enter_umask, "umask")
TRACE_SYSCALL(sys_enter_umount, "umount")
TRACE_SYSCALL(sys_enter_unlink, "unlink")
TRACE_SYSCALL(sys_enter_unlinkat, "unlinkat")
TRACE_SYSCALL(sys_enter_unshare, "unshare")
TRACE_SYSCALL(sys_enter_userfaultfd, "userfaultfd") // 추가된 항목
TRACE_SYSCALL(sys_enter_ustat, "ustat")
TRACE_SYSCALL(sys_enter_utime, "utime")
TRACE_SYSCALL(sys_enter_utimensat, "utimensat")
TRACE_SYSCALL(sys_enter_utimes, "utimes")
TRACE_SYSCALL(sys_enter_vfork, "vfork")
TRACE_SYSCALL(sys_enter_vhangup, "vhangup")
TRACE_SYSCALL(sys_enter_vmsplice, "vmsplice")
TRACE_SYSCALL(sys_enter_wait4, "wait4")
TRACE_SYSCALL(sys_enter_waitid, "waitid")
TRACE_SYSCALL(sys_enter_write, "write")
TRACE_SYSCALL(sys_enter_writev, "writev")

char _license[] SEC("license") = "GPL";
