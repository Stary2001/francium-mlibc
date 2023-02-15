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

#include <stdio.h>

#include "syscall.h"

#define STUB_ONLY { /*show_backtrace();*/ __ensure(!"STUB_ONLY function was called"); __builtin_unreachable(); }
#define UNUSED(x) (void)(x);

namespace mlibc {
	int sys_anon_allocate(size_t size, void **pointer) {
		// Ensure this matches PagePermission on pain of death

		int e = map_to_errno(syscall_map_memory(0, size, 1, pointer));
		if(e == 0) memset(*pointer, 0xaa, size);
		return e;
	}

	int sys_anon_free(void *pointer, size_t size) {
		sys_libc_log("sys_anon_free stub");
		(void)pointer;
		(void)size;
		return 0;
	}

	int sys_vm_map(void *hint, size_t size, int prot, int flags, int fd, off_t offset, void **window) STUB_ONLY
	int sys_vm_unmap(void *pointer, size_t size) STUB_ONLY
}