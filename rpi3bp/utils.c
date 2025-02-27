#include "utils.h"

void *memset(void *dest, int value, size_t len) {
    unsigned char *ptr = (unsigned char *)dest; // Cast destination to a byte pointer
    unsigned char val = (unsigned char)value;  // Ensure the value is a byte

    while (len--) {
        *ptr++ = val; // Set each byte in the block to the value
    }

    return dest; // Return the original destination pointer
}

void *memcpy(void *dest, const void *src, size_t n) {
    // Cast the input pointers to char pointers for byte-wise manipulation
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;

    // Copy n bytes from src to dest
    for (size_t i = 0; i < n; i++) {
        d[i] = s[i];
    }

    // Return the destination pointer
    return dest;
}

int memcmp(const void *s1, const void *s2, size_t n) {
    // Cast input pointers to unsigned char pointers for byte-wise comparison
    const unsigned char *p1 = (const unsigned char *)s1;
    const unsigned char *p2 = (const unsigned char *)s2;

    // Compare n bytes of the two memory blocks
    for (size_t i = 0; i < n; i++) {
        if (p1[i] != p2[i]) {
            return (p1[i] - p2[i]); // Return the difference between the two bytes
        }
    }

    return 0; // Return 0 if the blocks are identical
}