rtdl_sources += files(
)

libc_sources += files(
	'generic/thread.cpp',
	'generic/memory.cpp',
	'generic/entry.cpp',
	'generic/misc.cpp',
	'generic/stub.cpp',
	'generic/files.cpp'
)

if host_machine.cpu_family() == 'aarch64'
	libc_sources += files(
#		'aarch64/aarch64_syscalls.s',
		'aarch64/thread-entry.S'
	)
elif host_machine.cpu_family() == 'x86_64'
	libc_sources += files(
#		'x86_64/x86_64-syscalls.s',
		'x86_64/thread-entry.S'
	)
else
	error('Unknown architecture')
endif

if not no_headers
	install_headers(
		'include/abi-bits/access.h',
		'include/abi-bits/auxv.h',
		'include/abi-bits/seek-whence.h',
		'include/abi-bits/vm-flags.h',
		'include/abi-bits/errno.h',
		'include/abi-bits/fcntl.h',
		'include/abi-bits/in.h',
		'include/abi-bits/stat.h',
		'include/abi-bits/signal.h',
#		'include/abi-bits/reboot.h',
		'include/abi-bits/resource.h',
		'include/abi-bits/socket.h',
		'include/abi-bits/termios.h',
		'include/abi-bits/time.h',
		'include/abi-bits/blkcnt_t.h',
		'include/abi-bits/blksize_t.h',
		'include/abi-bits/dev_t.h',
		'include/abi-bits/gid_t.h',
		'include/abi-bits/ino_t.h',
		'include/abi-bits/mode_t.h',
		'include/abi-bits/nlink_t.h',
		'include/abi-bits/pid_t.h',
		'include/abi-bits/uid_t.h',
		'include/abi-bits/wait.h',
		'include/abi-bits/limits.h',
		'include/abi-bits/utsname.h',
		'include/abi-bits/ptrace.h',
		'include/abi-bits/poll.h',
		'include/abi-bits/epoll.h',
		'include/abi-bits/packet.h',
		'include/abi-bits/inotify.h',
		'include/abi-bits/clockid_t.h',
		'include/abi-bits/shm.h',
		'include/abi-bits/mqueue.h',
		'include/abi-bits/suseconds_t.h',
		'include/abi-bits/fsfilcnt_t.h',
		'include/abi-bits/fsblkcnt_t.h',
		'include/abi-bits/socklen_t.h',
		'include/abi-bits/statfs.h',
		'include/abi-bits/statvfs.h',
		'include/abi-bits/ioctls.h',
		'include/abi-bits/xattr.h',
		subdir: 'abi-bits'
	)
endif

if not headers_only
	crt_src = files(host_machine.cpu_family() / 'crt-src/crt0.S')
	crt = custom_target('crt0',
		build_by_default: true,
		command: c_compiler.cmd_array() + ['-c', '-o', '@OUTPUT@', '@INPUT@'],
		input: crt_src,
		output: 'crt0.o',
		install: true,
		install_dir: get_option('libdir')
	)

	if host_machine.cpu_family() == 'x86_64'
		crt_pie = custom_target('Scrt1',
			build_by_default: true,
			command: c_compiler.cmd_array() + ['-fPIE', '-c', '-o', '@OUTPUT@', '@INPUT@'],
			input: 'x86_64/crt-src/Scrt1.S',
			output: 'Scrt1.o',
			install: true,
			install_dir: get_option('libdir')
		)
	endif
endif

