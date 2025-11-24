#include "user.h"

void main(void) {
    __asm__ __volatile__(
        "li a7, 1; li a0, 'M'; ecall\n"  // Debug: in main
    );
    
    putchar('H');
    putchar('e');
    putchar('l');
    putchar('l');
    putchar('o');
    putchar('!');
    putchar('\n');
    
    for (;;);
}