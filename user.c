#include "user.h"

extern char __stack_top[];

__attribute__((noreturn)) void exit(void) {
    for (;;);
}

void putchar(char ch) {
    // Inline system call - syscall number in a7, character in a0
    __asm__ __volatile__(
        "li a7, 1    \n"  // SYS_PUTCHAR = 1
        "mv a0, %0   \n"  // character to print
        "ecall       \n"
        :
        : "r"(ch)
        : "a0", "a7"
    );
}

__attribute__((section(".text.start")))
__attribute__((naked))
void start(void) {
    __asm__ __volatile__(
        "li a7, 1; li a0, '1'; ecall\n"  // Before sp setup
        "mv sp, %[stack_top]         \n"
        "li a7, 1; li a0, '2'; ecall\n"  // After sp setup
        "call main                   \n"
        "li a7, 1; li a0, '3'; ecall\n"  // After main
        "call exit                   \n"
        :: [stack_top] "r" (__stack_top)
    );
}
