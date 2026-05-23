/* Toy binary for ida-func-call-rank manual verification.
 *
 * Build:
 *     gcc -O0 -fno-inline -fno-omit-frame-pointer toy.c -o toy
 *     # or on Windows MSVC:
 *     cl /Od /Gy toy.c
 *
 * Open the resulting binary in IDA, run the plugin, and verify that the
 * `Calls In` / `Unique Callers` columns match the expectations below.
 *
 * Expected (after filters: lib/thunk/import hidden):
 *
 *   hash:
 *     Calls In       = 4
 *     Unique Callers = 3      (decrypt, parse_a, parse_b)
 *
 *   decrypt:
 *     Calls In       = 1      (main)
 *     Unique Callers = 1
 *     Calls Out      = 1      (hash)
 *
 *   parse_a:
 *     Calls In       = 1
 *     Calls Out      = 2      (hash, hash)
 *     Unique Callees = 1
 *
 *   unused:
 *     Calls In       = 0
 *     Unique Callers = 0
 *
 *   fact:
 *     Recursive Calls >= 1
 */

#include <stdio.h>

__attribute__((noinline)) void hash(void)       { puts("h"); }
__attribute__((noinline)) void decrypt(void)    { hash(); }
__attribute__((noinline)) void parse_a(void)    { hash(); hash(); }
__attribute__((noinline)) void parse_b(void)    { hash(); }
__attribute__((noinline)) void unused(void)     { puts("u"); }

__attribute__((noinline)) int fact(int n) {
    if (n <= 1) return 1;
    return n * fact(n - 1);
}

int main(void) {
    decrypt();
    parse_a();
    parse_b();
    printf("%d\n", fact(5));
    return 0;
}
