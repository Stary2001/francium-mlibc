#include <mlibc/thread-entry.hpp>
#include <mlibc/all-sysdeps.hpp>
#include <mlibc/tcb.hpp>
#include <bits/ensure.h>
#include <sys/mman.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#include "syscall.h"

extern "C" void __mlibc_enter_thread(void *entry, void *user_arg, Tcb *tcb) {
	// Wait until our parent sets up the TID.
	while(!__atomic_load_n(&tcb->tid, __ATOMIC_RELAXED))
		mlibc::sys_futex_wait(&tcb->tid, 0, nullptr);

	if(mlibc::sys_tcb_set(tcb))
		__ensure(!"sys_tcb_set() failed");

	void *(*func)(void *) = reinterpret_cast<void *(*)(void *)>(entry);
	auto result = func(user_arg);

	auto self = reinterpret_cast<Tcb *>(tcb);

	self->returnValue = result;
	__atomic_store_n(&self->didExit, 1, __ATOMIC_RELEASE);
	mlibc::sys_futex_wake(&self->didExit);

	mlibc::sys_thread_exit();
}

namespace mlibc {
	static constexpr size_t default_stacksize = 0x400000;

	int sys_prepare_stack(void **stack, void *entry, void *user_arg, void *tcb, size_t *stack_size, size_t *guard_size) {
		uintptr_t *sp;
		if (!*stack_size)
			*stack_size = default_stacksize;
		*guard_size = 0;

		printf("Got stacksize %08x\n", *stack_size);

		if (*stack) {
			sp = reinterpret_cast<uintptr_t *>(*stack);
		} else {
			__ensure(!sys_anon_allocate(*stack_size, stack));
			sp = reinterpret_cast<uintptr_t *>(reinterpret_cast<uintptr_t>(*stack) + *stack_size);
		}

		*--sp = reinterpret_cast<uintptr_t>(0ul);
		*--sp = reinterpret_cast<uintptr_t>(tcb);
		*--sp = reinterpret_cast<uintptr_t>(user_arg);
		*--sp = reinterpret_cast<uintptr_t>(entry);
		*stack = reinterpret_cast<void*>(sp);
		return 0;
	}
} //namespace mlibc
