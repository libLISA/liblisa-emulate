#include <stdint.h>

void f0(uint64_t x0) {
    register uint64_t a __asm__("rax") = x0;
    register uint64_t b __asm__("rdi") = x0;
    asm(
        "xor    %1,%1\n"
        "rclb   $9, %%al\n"
        "jno    skip\n"
        "mov    $60, %%al\n"
        "syscall\n"
        "skip:\n"
        : /* no outputs */
        : "r" (a), "r" (b)
    );
}

int main() {
    f0(0);
    f0(0x80);
    return 42;
}