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
	int sys_open(const char *pathname, int flags, mode_t mode, int *fd) {

	}

	int sys_read(int fd, void *buf, size_t count, ssize_t *bytes_read) {

	}

	int sys_seek(int fd, off_t offset, int whence, off_t *new_offset) {

	}

	int sys_close(int fd) {
		
	}

	[[gnu::weak]] int sys_stat(fsfd_target fsfdt, int fd, const char *path, int flags,
			struct stat *statbuf);
}