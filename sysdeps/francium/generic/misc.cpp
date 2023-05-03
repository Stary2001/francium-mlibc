#include <bits/ensure.h>
#include <mlibc/allocator.hpp>
#include <mlibc/debug.hpp>
#include <mlibc/all-sysdeps.hpp>
#include <mlibc/thread-entry.hpp>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <asm/ioctls.h>
#include <stdlib.h>
#include <abi-bits/fcntl.h>
#include <stdio.h>

#include "syscall.h"
#include <assert.h>

namespace mlibc {
	void sys_libc_log(const char *message) {
		char buff[512];
		int len = snprintf(buff, 511, "%s\n", message);
		buff[len] = 0;

		syscall_debug_output(buff, len);
	}
	
	[[noreturn]] void sys_libc_panic() {
		syscall_exit_process();
	}

	void sys_exit(int) {
		syscall_exit_process();
	}

	int sys_futex_tid() {
		return syscall_get_thread_id();
	}

	int sys_futex_wait(int *pointer, int expected, const struct timespec *timeout_timespec) {
		uint64_t timeout_ns = 0;

		if(timeout_timespec != nullptr) {
			timeout_ns = timeout_timespec->tv_sec * 1000000000 + timeout_timespec->tv_nsec;		
		}

		return map_to_errno(syscall_futex_wait(pointer, expected, timeout_ns));
	}

	int sys_futex_wake(int *pointer) {
		//printf("futex wake %p\n", pointer);
		return map_to_errno(syscall_futex_wake(pointer));
	}

	pid_t sys_getpid() {
		return syscall_get_process_id();
	}

	int sys_tcb_set(void *pointer) {
		#if defined(__x86_64__)
			syscall_bodge(SET_FS, reinterpret_cast<uintptr_t>(pointer));
		#elif defined(__aarch64__)
			uintptr_t thread_data = reinterpret_cast<uintptr_t>(pointer) + sizeof(Tcb) - 0x10;
			asm volatile ("msr tpidr_el0, %0" :: "r"(thread_data));
		#elif defined(__riscv)
        	uintptr_t thread_data = reinterpret_cast<uintptr_t>(pointer) + sizeof(Tcb);
        	asm volatile ("mv tp, %0" :: "r"(thread_data));
		#endif
		return 0;
	}

	int sys_getentropy(void *buffer, size_t length) {
		// die
		(void) buffer;
		(void) length;
		return 0;
	}

	int sys_clone(void *tcb, pid_t *pid_out, void *stack) {
		// etc
		(void)tcb;

		Handle thread_handle = 0;
		int r = map_to_errno(syscall_create_thread(__mlibc_start_thread, stack, &thread_handle));

		// TODO: This is meant to return a thread handle, not a thread ID.
		*pid_out = (pid_t) thread_handle;
		return r;
	}

	int sys_clock_get(int clock, time_t *secs, long *nanos) {
		// Fuck it you get monotonic anyway
		//assert(clock == CLOCK_MONOTONIC);

		uint64_t ticks = syscall_get_system_tick();
		*secs = ticks / 1000000000;
		*nanos = ticks % 1000000000;
		return 0;
	}

	int sys_isatty(int fd) {
		return 0;
	}

	int sys_kill(int pid, int sig) {
		printf("kill %i %i %i\n", pid, sig, SIGABRT);
		// TODO: kinda hacky lol
		if(sig == SIGABRT) {
			syscall_break();
		}
		return 0;
	}

	int sys_sigaction(int, const struct sigaction *__restrict, struct sigaction *__restrict) {
		// Ignore
		//sys_libc_log("sys_sigaction ignored");
		return 0;
	}

	int sys_sigprocmask(int how, const sigset_t *__restrict set, sigset_t *__restrict retrieve) {
		// Ignore
		//sys_libc_log("sys_sigprocmask ignored");
		return 0;
	}
}
