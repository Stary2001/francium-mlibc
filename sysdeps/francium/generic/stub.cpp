#include <stdio.h>
#include <bits/ensure.h>
#include <mlibc/all-sysdeps.hpp>

#define UNW_LOCAL_ONLY
#include <unwind.h>

/*_Unwind_Reason_Code trace_func(struct _Unwind_Context *context, void *arg) {
        int *depth = (int*) arg;
        printf("%i %016lx", *depth, _Unwind_GetIP(context));
        (*depth)++;
        return _URC_NO_REASON;
}

void show_backtrace (void) {
        int depth = 0;
	printf("Backtrace??\n");
        _Unwind_Backtrace(trace_func, &depth);
	printf("Backtrace??\n");
}*/

#define STUB_ONLY { /*show_backtrace();*/ __ensure(!"STUB_ONLY function was called"); __builtin_unreachable(); }
#define UNUSED(x) (void)(x);

namespace mlibc {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

gid_t sys_getegid() STUB_ONLY
gid_t sys_getgid() STUB_ONLY
int sys_accept(int fd, int *newfd, struct sockaddr *addr_ptr, socklen_t *addr_length) STUB_ONLY
int sys_access(const char *path, int mode) STUB_ONLY
int sys_before_cancellable_syscall(ucontext_t *uctx) STUB_ONLY
int sys_bind(int fd, const struct sockaddr *addr_ptr, socklen_t addr_length) STUB_ONLY
int sys_chdir(const char *path) STUB_ONLY
int sys_chmod(const char *pathname, mode_t mode) STUB_ONLY
int sys_chroot(const char *path) STUB_ONLY
int sys_clock_getres(int clock, time_t *secs, long *nanos) STUB_ONLY
int sys_connect(int fd, const struct sockaddr *addr_ptr, socklen_t addr_length) STUB_ONLY
int sys_delete_module(const char *name, unsigned flags) STUB_ONLY
int sys_dup2(int fd, int flags, int newfd) STUB_ONLY
int sys_dup(int fd, int flags, int *newfd) STUB_ONLY
int sys_epoll_create(int flags, int *fd) STUB_ONLY
int sys_epoll_ctl(int epfd, int mode, int fd, struct epoll_event *ev) STUB_ONLY
int sys_epoll_pwait(int epfd, struct epoll_event *ev, int n, int timeout, const sigset_t *sigmask, int *raised) STUB_ONLY
int sys_eventfd_create(unsigned int initval, int flags, int *fd) STUB_ONLY
int sys_execve(const char *path, char *const argv[], char *const envp[]) STUB_ONLY
int sys_faccessat(int dirfd, const char *pathname, int mode, int flags) STUB_ONLY
int sys_fadvise(int fd, off_t offset, off_t length, int advice) STUB_ONLY
int sys_fallocate(int fd, off_t offset, size_t size) STUB_ONLY
int sys_fchdir(int fd) STUB_ONLY
int sys_fchmodat(int fd, const char *pathname, mode_t mode, int flags) STUB_ONLY
int sys_fchmod(int fd, mode_t mode) STUB_ONLY
int sys_fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags) STUB_ONLY
int sys_fcntl(int fd, int request, va_list args, int *result) STUB_ONLY
int sys_fdatasync(int fd) STUB_ONLY
int sys_flock(int fd, int options) STUB_ONLY
int sys_fork(pid_t *child) STUB_ONLY
int sys_fremovexattr(int fd, const char *name) STUB_ONLY
int sys_fstatfs(int fd, struct statfs *buf) STUB_ONLY
int sys_fstatvfs(int fd, struct statvfs *out) STUB_ONLY
int sys_fsync(int fd) STUB_ONLY
int sys_ftruncate(int fd, size_t size) STUB_ONLY
int sys_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask) STUB_ONLY
int sys_getcpu(int *cpu) STUB_ONLY
int sys_getcwd(char *buffer, size_t size) STUB_ONLY

int sys_getgroups(size_t size, const gid_t *list, int *ret) STUB_ONLY
int sys_gethostname(char *buffer, size_t bufsize) STUB_ONLY
int sys_getitimer(int which, struct itimerval *curr_value) STUB_ONLY
int sys_getpriority(int which, id_t who, int *value) STUB_ONLY
int sys_getrlimit(int resource, struct rlimit *limit) STUB_ONLY
int sys_getrusage(int scope, struct rusage *usage) STUB_ONLY
int sys_getsockopt(int fd, int layer, int number, void *__restrict buffer, socklen_t *__restrict size) STUB_ONLY
int sys_init_module(void *module, unsigned long length, const char *args) STUB_ONLY
int sys_inotify_add_watch(int ifd, const char *path, uint32_t mask, int *wd) STUB_ONLY
int sys_inotify_create(int flags, int *fd) STUB_ONLY
int sys_inotify_rm_watch(int ifd, int wd) STUB_ONLY
int sys_ioctl(int fd, unsigned long request, void *arg, int *result) STUB_ONLY

int sys_klogctl(int type, char *bufp, int len, int *out) STUB_ONLY
int sys_linkat(int olddirfd, const char *old_path, int newdirfd, const char *new_path, int flags) STUB_ONLY
int sys_link(const char *old_path, const char *new_path) STUB_ONLY
int sys_listen(int fd, int backlog) STUB_ONLY
int sys_madvise(void *addr, size_t length, int advice) STUB_ONLY
int sys_memfd_create(const char *name, int flags, int *fd) STUB_ONLY
int sys_mkdirat(int dirfd, const char *path, mode_t mode) STUB_ONLY
int sys_mkdir(const char *path, mode_t mode) STUB_ONLY
int sys_mkfifoat(int dirfd, const char *path, int mode) STUB_ONLY
int sys_mknodat(int dirfd, const char *path, int mode, int dev) STUB_ONLY
int sys_mlockall(int flags) STUB_ONLY
int sys_mlock(const void *addr, size_t len) STUB_ONLY
int sys_mount(const char *, const char *, const char *, unsigned long, const void *) STUB_ONLY
int sys_msg_recv(int fd, struct msghdr *hdr, int flags, ssize_t *length) STUB_ONLY
int sys_msg_send(int fd, const struct msghdr *hdr, int flags, ssize_t *length) STUB_ONLY
int sys_msync(void *addr, size_t length, int flags) STUB_ONLY
int sys_openat(int dirfd, const char *path, int flags, mode_t mode, int *fd) STUB_ONLY
int sys_open_dir(const char *path, int *handle) STUB_ONLY
int sys_pause() STUB_ONLY
int sys_peername(int fd, struct sockaddr *addr_ptr, socklen_t max_addr_length, socklen_t *actual_length) STUB_ONLY
int sys_pipe(int *fds, int flags) STUB_ONLY
int sys_poll(struct pollfd *fds, nfds_t count, int timeout, int *num_events) STUB_ONLY
int sys_prctl(int option, va_list va, int *out) STUB_ONLY
int sys_pread(int fd, void *buf, size_t n, off_t off, ssize_t *bytes_read) STUB_ONLY
//int sys_prepare_stack(void **stack, void *entry, void *user_arg, void* tcb, size_t *stack_size, size_t *guard_size) STUB_ONLY
int sys_pselect(int num_fds, fd_set *read_set, fd_set *write_set, fd_set *except_set, const struct timespec *timeout, const sigset_t *sigmask, int *num_events) STUB_ONLY
int sys_ptrace(long req, pid_t pid, void *addr, void *data, long *out) STUB_ONLY
int sys_pwrite(int fd, const void *buf, size_t n, off_t off, ssize_t *bytes_read) STUB_ONLY
int sys_read_entries(int handle, void *buffer, size_t max_size, size_t *bytes_read) STUB_ONLY
int sys_readlink(const char *path, void *buffer, size_t max_size, ssize_t *length) STUB_ONLY
int sys_reboot(int cmd) STUB_ONLY
int sys_removexattr(const char *path, const char *name) STUB_ONLY
int sys_renameat(int olddirfd, const char *old_path, int newdirfd, const char *new_path) STUB_ONLY
int sys_rename(const char *path, const char *new_path) STUB_ONLY
int sys_rmdir(const char *path) STUB_ONLY
int sys_setegid(gid_t egid) STUB_ONLY
int sys_seteuid(uid_t euid) STUB_ONLY
int sys_setgid(gid_t gid) STUB_ONLY
int sys_setgroups(size_t size, const gid_t *list) STUB_ONLY
int sys_sethostname(const char *buffer, size_t bufsize) STUB_ONLY
int sys_setitimer(int which, const struct itimerval *new_value, struct itimerval *old_value) STUB_ONLY
int sys_setpgid(pid_t pid, pid_t pgid) STUB_ONLY
int sys_setpriority(int which, id_t who, int prio) STUB_ONLY
int sys_setregid(gid_t rgid, gid_t egid) STUB_ONLY
int sys_setresgid(gid_t rgid, gid_t egid, gid_t sgid) STUB_ONLY
int sys_setresuid(uid_t ruid, uid_t euid, uid_t suid) STUB_ONLY
int sys_setreuid(uid_t ruid, uid_t euid) STUB_ONLY
int sys_setrlimit(int resource, const struct rlimit *limit) STUB_ONLY
int sys_setsid(pid_t *sid) STUB_ONLY
int sys_setsockopt(int fd, int layer, int number, const void *buffer, socklen_t size) STUB_ONLY
int sys_setuid(uid_t uid) STUB_ONLY
int sys_sigaction(int, const struct sigaction *__restrict, struct sigaction *__restrict) {
	// Ignore
	//sys_libc_log("sys_sigaction ignored");
	return 0;
}
int sys_sigaltstack(const stack_t *ss, stack_t *oss) STUB_ONLY
int sys_signalfd_create(const sigset_t *, int flags, int *fd) STUB_ONLY
int sys_sigprocmask(int how, const sigset_t *__restrict set, sigset_t *__restrict retrieve) {
	// Ignore
	//sys_libc_log("sys_sigprocmask ignored");
	return 0;
}
int sys_sigsuspend(const sigset_t *set) STUB_ONLY
int sys_sleep(time_t *secs, long *nanos) STUB_ONLY
int sys_socket(int family, int type, int protocol, int *fd) STUB_ONLY
int sys_socketpair(int domain, int type_and_flags, int proto, int *fds) STUB_ONLY
int sys_sockname(int fd, struct sockaddr *addr_ptr, socklen_t max_addr_length, socklen_t *actual_length) STUB_ONLY
int sys_statfs(const char *path, struct statfs *buf) STUB_ONLY
int sys_stat(fsfd_target fsfdt, int fd, const char *path, int flags, struct stat *statbuf) STUB_ONLY
int sys_statvfs(const char *path, struct statvfs *out) STUB_ONLY
int sys_symlinkat(const char *target_path, int dirfd, const char *link_path) STUB_ONLY
int sys_symlink(const char *target_path, const char *link_path) STUB_ONLY
int sys_sysinfo(struct sysinfo *info) STUB_ONLY
int sys_tcdrain(int) STUB_ONLY
int sys_tcflow(int, int) STUB_ONLY
int sys_tcgetattr(int fd, struct termios *attr) STUB_ONLY
int sys_tcsetattr(int, int, const struct termios *attr) STUB_ONLY
int sys_tgkill(int tgid, int tid, int sig) STUB_ONLY
int sys_timerfd_create(int clockid, int flags, int *fd) STUB_ONLY
int sys_timerfd_settime(int fd, int flags, const struct itimerspec *value, struct itimerspec *oldvalue) STUB_ONLY
int sys_times(struct tms *tms, clock_t *out) STUB_ONLY
int sys_ttyname(int fd, char *buf, size_t size) STUB_ONLY
int sys_umask(mode_t mode, mode_t *old) STUB_ONLY
int sys_umount2(const char *target, int flags) STUB_ONLY
int sys_uname(struct utsname *buf) STUB_ONLY
int sys_unlinkat(int fd, const char *path, int flags) STUB_ONLY
int sys_utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags) STUB_ONLY
int sys_vm_protect(void *pointer, size_t size, int prot) STUB_ONLY
int sys_vm_readahead(void *pointer, size_t size) STUB_ONLY
int sys_vm_remap(void *pointer, size_t size, size_t new_size, void **window) STUB_ONLY
int sys_waitpid(pid_t pid, int *status, int flags, struct rusage *ru, pid_t *ret_pid) STUB_ONLY
pid_t sys_getpgid(pid_t pid, pid_t *pgid) STUB_ONLY
//pid_t sys_getpid() {
pid_t sys_getppid() STUB_ONLY
pid_t sys_getsid(pid_t pid, pid_t *sid) STUB_ONLY
pid_t sys_gettid() STUB_ONLY
uid_t sys_geteuid() STUB_ONLY
uid_t sys_getuid() STUB_ONLY
void sys_sync() STUB_ONLY
void sys_yield() STUB_ONLY
[[noreturn]] void sys_thread_exit() STUB_ONLY

int sys_clock_get(int clock, time_t *secs, long *nanos) STUB_ONLY
#pragma GCC diagnostic pop
}
