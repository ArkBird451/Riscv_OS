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

void readfile(const char *filename, char *buf, int size) {
    __asm__ __volatile__(
        "mv a0, %0   \n"  // filename
        "mv a1, %1   \n"  // buffer
        "mv a2, %2   \n"  // size
        "li a7, 2    \n"  // SYS_READFILE = 2
        "ecall       \n"
        :
        : "r"(filename), "r"(buf), "r"(size)
        : "a0", "a1", "a2", "a7"
    );
}

void listdir(void) {
    __asm__ __volatile__(
        "li a7, 3    \n"  // SYS_LISTDIR = 3
        "ecall       \n"
        :
        :
        : "a7"
    );
}

__attribute__((section(".text.start")))
__attribute__((naked))
void start(void) {
    __asm__ __volatile__(
        "mv sp, %[stack_top] \n"
        "call main           \n"
        "call exit           \n"
        :: [stack_top] "r" (__stack_top)
    );
}
