#include "gpio.h"


void set_gpio_as_out(unsigned int pin){
    volatile unsigned int *reg1 = GPFSEL0 + ((pin / 10)); // which GPFSELn?
    unsigned int shift = (pin % 10) * 3; // bit shift inside a GPFSELn

    unsigned int val = *reg1;
    val &= ~(7 << shift); // reserve all rest bits
    val |=  (1 << shift); // set target pin's function to OUTPUT
    *reg1 = val; // write to set
}

inline void set_pin_high(unsigned int pin){
    unsigned int reg_offset = (pin >> 5); // which GPSETn/GPCLRn?
    register volatile unsigned int * reg_offset0 = (unsigned int *)(GPCLR0 + reg_offset); // GPSETn
    register unsigned int reg_mask = 1 << (pin & 0x1f); // % 32 for masking
    *reg_offset0 = reg_mask; // SET
}

inline void set_pin_low(unsigned int pin){
    unsigned int reg_offset = (pin >> 5); // which GPSETn/GPCLRn?
    register volatile unsigned int * reg_offset1 = (unsigned int *)(GPSET0 + reg_offset); // GPCLRn
    register unsigned int reg_mask = 1 << (pin & 0x1f); // % 32 for masking
    *reg_offset1 = reg_mask; // CLEAR
}