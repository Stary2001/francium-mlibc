#include <bits/ensure.h>
#include <mlibc/allocator.hpp>
#include <mlibc/debug.hpp>
#include <mlibc/all-sysdeps.hpp>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <asm/ioctls.h>
#include <stdlib.h>
#include <abi-bits/fcntl.h>

#include "syscall.h"

int map_to_errno(ResultCode r) {
	if(r == 0) return 0;
	return ENOSYS;
}

namespace mlibc {
	void sys_libc_log(const char *message) {
		syscall_debug_output(message, strlen(message));
		syscall_debug_output("\n", 1);
	}
	
	[[noreturn]] void sys_libc_panic() {
		syscall_exit_process();
	}

	void sys_exit(int) {
		syscall_exit_process();
	}

	int sys_anon_allocate(size_t size, void **pointer) {
		/*
			pub const PROT_EXEC: u32 = 0x0001;
			pub const PROT_WRITE: u32 = 0x0002;
			pub const PROT_READ: u32 = 0x0004;
		*/
		int e = map_to_errno(syscall_map_memory(0, size, 2|4, pointer));
		if(e == 0) memset(*pointer, 0, size);
		return e;
	}

	int sys_anon_free(void *pointer, size_t size) {
		sys_libc_log("sys_anon_free stub");
		return 0;
	}

	int sys_futex_tid() {
		sys_libc_log("sys_futex_tid stub");
		return 0;
	}

	int sys_tcb_set(void *pointer) {
		sys_libc_log("sys_tcb_set hit");
		#if defined(__aarch64__)
		uintptr_t thread_data = reinterpret_cast<uintptr_t>(pointer) + sizeof(Tcb) - 0x10;
        asm volatile ("msr tpidr_el0, %0" :: "r"(thread_data));
		#else
			STUB_ONLY
		#endif
		return 0;
	}
}