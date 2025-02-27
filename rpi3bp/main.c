/*
 * Copyright (C) 2018 bzt (bztsrc@github)
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */
#include "uart.h"
#include "utils.h"
#include "aes.h"
#include "gpio.h"

/* AES test code */
static int test_encrypt_ecb(register volatile uint32_t * up, register volatile uint32_t * down, register uint32_t mask)
{
#if defined(AES256)
    uint8_t key[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                      0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
    uint8_t out[] = { 0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8 };
#elif defined(AES192)
    uint8_t key[] = { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
                      0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b };
    uint8_t out[] = { 0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f, 0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5, 0xcc };
#elif defined(AES128)
    uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    uint8_t out[] = { 0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97 };
#endif

    uint8_t in[]  = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
    struct AES_ctx ctx;

    AES_init_ctx(&ctx, key);
    *up = mask; // trigger high
    AES_ECB_encrypt(&ctx, in);
    *down = mask; // trigger down

    printf("ECB encrypt: ");

    if (0 == memcmp((char*) out, (char*) in, 16)) {
        printf("SUCCESS!\n");
	    return(0);
    } else {
        printf("FAILURE!\n");
	    return(1);
    }
}
/* end */

// Function pointer type for the target function
typedef int (*crypto_verify_t)(void *data_ptr, unsigned int data_len, 
                                void *sig_ptr, void *pk_ptr, 
                                void *sig_alg);


extern uint8_t _binfw_base;
uint8_t * FW_BASE = &_binfw_base;
uint64_t func_offset = 0x93a8;


// Static buffers for function arguments
#define DATA_SIZE 0x50
#define SIG_SIZE 0x40
#define SIG_ALG_SIZE 32
#define PK_SIZE 0x20

static uint8_t data_buffer[DATA_SIZE] = {
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41
};     // Data buffer
static uint8_t sig_buffer[SIG_SIZE] = {
    0x44, 0xf5, 0xa8, 0xf5, 0xdc, 0x01, 0xc5, 0x95, 0x8f, 0x85, 0x7a, 0x88, 0x6c, 0x1f, 0xcc, 0x71, 0x06, 0x61, 0xf9, 0x01, 0xfd, 0x60, 0x39, 0x56, 0xb6, 0xdb, 0x5d, 0x33, 0x44, 0x83, 0x3d, 0x53, 0x51, 0xf0, 0xd8, 0xa1, 0x0c, 0xc4, 0x7c, 0x29, 0xaf, 0x2a, 0xf0, 0xf1, 0x84, 0xf5, 0xf0, 0xc5, 0xef, 0xf2, 0x5a, 0x72, 0x42, 0x43, 0x27, 0x50, 0xd8, 0xcb, 0xb5, 0xb2, 0x7f, 0x67, 0x2c, 0x01
};       // Signature buffer
static uint8_t sig_alg_buffer[SIG_ALG_SIZE]; // Signature algorithm buffer
static uint8_t pk_buffer[PK_SIZE] = {
    0x79, 0xb5, 0x56, 0x2e, 0x8f, 0xe6, 0x54, 0xf9, 0x40, 0x78, 0xb1, 0x12, 0xe8, 0xa9, 0x8b, 0xa7, 0x90, 0x1f, 0x85, 0x3a, 0xe6, 0x95, 0xbe, 0xd7, 0xe0, 0xe3, 0x91, 0x0b, 0xad, 0x04, 0x96, 0x64
};         // Public key buffer

// GPIO setting
#define TRIGGER_OUT_PIN 16  

void main()
{
    // Cast the binary start address to the function pointer
    crypto_verify_t verify_func = (crypto_verify_t)(func_offset + FW_BASE);

    // set up serial console
    uart_init();

    // START set up gpio
    const uint32_t pin = TRIGGER_OUT_PIN;

    volatile uint32_t *GPFSELn = GPFSEL0 + ((pin / 10)); // which GPFSELn? note that GPFSEL0 is a uint32_t *!
    uint32_t shift = (pin % 10) * 3; // bit shift inside a GPFSELn

    uint32_t val = *(volatile uint32_t *)GPFSELn;
    val &= ~(7 << shift); // reserve all rest bits
    val |=  (1 << shift); // set target pin's function to OUTPUT
    *(volatile uint32_t *)GPFSELn = val; // write to set

    uint32_t reg_offset = (pin >> 5); // which GPSETn/GPCLRn?

    register volatile uint32_t * GPSETn = (uint32_t *)(GPSET0 + reg_offset); // GPSETn
    register volatile uint32_t * GPCLRn = (uint32_t *)(GPCLR0 + reg_offset); // GPCLRn

    register uint32_t reg_mask = 1 << (pin & 0x1f); // % 32 for masking
    *GPCLRn = reg_mask; // clear the output
    // END set up gpio

    printf("GPFSELn: %lx\n", GPFSELn);
    printf("GPSETn: %lx\n", GPSETn);
    printf("GPCLRn: %lx\n", GPCLRn);
    printf("reg_mask: %lx\n", reg_mask);

    printf("The verify_func offset is %x\n", verify_func);

    // Initialize the buffers with dummy data
    // memset(data_buffer, 0x00, DATA_SIZE); // Fill data buffer with dummy data
    // memset(sig_buffer, 0x00, SIG_SIZE);   // Fill signature buffer with dummy data
    // memset(sig_alg_buffer, 0x00, SIG_ALG_SIZE); // Fill signature algorithm buffer
    // memset(pk_buffer, 0x00, PK_SIZE);     // Fill public key buffer with dummy data

    // Prepare function arguments
    void *data_ptr = data_buffer;
    unsigned int data_len = DATA_SIZE;

    void *sig_ptr = sig_buffer;
    unsigned int sig_len = SIG_SIZE;

    void *sig_alg = sig_alg_buffer;
    unsigned int sig_alg_len = SIG_ALG_SIZE;

    void *pk_ptr = pk_buffer;
    unsigned int pk_len = PK_SIZE;

    while(1){
        char cmd = uart_getc();
        printf("CMD %c start\n", cmd);
        switch (cmd){
            case 'A':
                test_encrypt_ecb(GPSETn, GPCLRn, reg_mask);
                break;
            case 'T':
                // toggle the pin for test
                for(int i=0;i<1e9+7;++i){
                    *GPSETn |= reg_mask;
                    *GPCLRn |= reg_mask;
                }
                break;
            case 'H':
                *GPSETn |= reg_mask;
                break;
            case 'L':
                *GPCLRn |= reg_mask;
                break;
            case 'V':
                // Call the function and retrieve the result
                if (verify_func) {
                    *GPSETn |= reg_mask; // trigger high
                    int result = verify_func(data_ptr, data_len, sig_ptr, pk_ptr, sig_alg);
                    *GPCLRn |= reg_mask; // trigger low

                    // Check the result (for debugging or further processing)
                    if (result) {
                        // Success
                        printf("Sucess!\n");
                    } else {
                        // Failure
                        printf("Failure!\n");
                    }
                }
                break;
            default:
                break;
        }
        printf("done!\n");
    }

    // echo everything back
    while(1) {
        uart_send(uart_getc());
    }
}
