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

namespace mlibc {
	void sys_libc_log(const char *message) {

	}
	
	[[noreturn]] void sys_libc_panic() {

	}

	int sys_tcb_set(void *pointer) {

	}

	[[gnu::weak]] int sys_futex_tid();
	int sys_futex_wait(int *pointer, int expected, const struct timespec *time);
	int sys_futex_wake(int *pointer);

	int sys_anon_allocate(size_t size, void **pointer) {

	}

	int sys_anon_free(void *pointer, size_t size) {

	}
	// mlibc assumes that anonymous memory returned by sys_vm_map() is zeroed by the kernel / whatever is behind the sysdeps
	int sys_vm_map(void *hint, size_t size, int prot, int flags, int fd, off_t offset, void **window);
	int sys_vm_unmap(void *pointer, size_t size);
	[[gnu::weak]] int sys_vm_protect(void *pointer, size_t size, int prot);
}