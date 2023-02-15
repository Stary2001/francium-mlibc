
.section .text
.global __mlibc_start_thread
__mlibc_start_thread:
	pop %rdi
	pop %rsi
	pop %rdx
	pop %rax
	call __mlibc_enter_thread

.section .note.GNU-stack,"",%progbits

