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
#include <stdio.h>
#include <abi-bits/fcntl.h>

#include "syscall.h"

#define STUB_ONLY { __ensure(!"STUB_ONLY function was called"); __builtin_unreachable(); }
#define UNUSED(x) (void)(x);

namespace mlibc {
	#pragma GCC diagnostic push
	#pragma GCC diagnostic ignored "-Wunused-parameter"

	int sys_open(const char *pathname, int flags, mode_t mode, int *fd) {
		printf("open: '%s'\n", pathname);
		STUB_ONLY
	}

	int sys_read(int fd, void *buf, size_t count, ssize_t *bytes_read) STUB_ONLY
	int sys_write(int fd, const void *buffer, size_t count, ssize_t *written) {
		if(fd == 1 || fd == 2) {
			syscall_debug_output((const char*)buffer, count);
			*written = count;
			return 0;
		} else {
			*written = 0;
			return -ENOSYS;
		}
	}
	int sys_seek(int fd, off_t offset, int whence, off_t *new_offset) {
			sys_libc_log("seek stub");
	return 0;
	}
	int sys_close(int fd) STUB_ONLY

	#pragma GCC diagnostic pop

	//[[gnu::weak]] int sys_stat(fsfd_target fsfdt, int fd, const char *path, int flags,
	//		struct stat *statbuf) STUB_ONLY
}