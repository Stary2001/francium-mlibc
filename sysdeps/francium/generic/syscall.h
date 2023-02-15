#include <stdint.h>
#include <stdlib.h>
#include <errno.h>

typedef uint32_t ResultCode;
typedef uint32_t Handle;

#define GET_FS 0
#define SET_FS 1

extern "C" {
	[[noreturn]] void syscall_break();
	ResultCode syscall_debug_output(const char *s, size_t len);
	//ResultCode syscall_create_port(tag: u64, handle_out: *mut Handle);
	//ResultCode syscall_connect_to_named_port(tag: u64, handle_out: *mut Handle);
	[[noreturn]] void syscall_exit_process();
	//ResultCode syscall_close_handle(h: Handle);
	//ResultCode syscall_ipc_request(session_handle: Handle, ipc_buffer: *mut u8) -> ;
	//ResultCode syscall_ipc_reply(session_handle: Handle, ipc_buffer: *mut u8) -> ;
	//ResultCode syscall_ipc_receive(sessions: *const Handle, num_sessions: size_t, ipc_buffer: *mut u8, index_out: *mut size_t) -> ;
	//ResultCode syscall_ipc_accept(session_handle: Handle, handle_out: *mut Handle) -> ;
	uint64_t syscall_get_process_id();
	//ResultCode syscall_connect_to_port_handle(h: u32, handle_out: *mut Handle) -> ;
	ResultCode syscall_map_memory(uintptr_t address, size_t length, uint64_t permission, void **addr_out);
	void syscall_sleep_ns(uint64_t ns);
	uintptr_t syscall_bodge(uint32_t key, uintptr_t addr);
	uintptr_t syscall_get_thread_id();
	ResultCode syscall_create_thread(void (*entry_point)() , void *stack_top, Handle *out);
	ResultCode syscall_futex_wait(int *addr, int expected, uint64_t timeout);
	ResultCode syscall_futex_wake(int *addr);
	uint64_t syscall_get_system_tick();
}

static inline int map_to_errno(ResultCode r) {
	if(r == 0) return 0;
	return ENOSYS;
}