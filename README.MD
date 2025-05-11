# Locating Cryptographic Procedures in SoC Secure Boot by Semi-automated Side-Channel Analysis

## Trace collection

### RK3588

When collecting the electromagnetic sideband trace from a Banana Pi BPI-M7 development board, you need to remove the metal protective cover of its CPU, as shown in the figure below:

![alt text](imgs/rk3588.jpg)

### RPI3B+

Even after removing the metal protective cover, the front-side CPU leak of the Raspberry Pi 3b+ is very insignificant, so you need to probe the coupling capacitances from the back.

![alt text](imgs/rpi3B+.jpg)

## Trace processing

Please refer to the trace_processing folder. All traces used in the paper could be downloaded at [here](https://1drv.ms/u/c/a7c5ff15f8f8c857/EYkpfS0ytbFJuSsPkWYgNOcB65V08AVAd50HXf6FpIWLyQ?e=MGg2f8).
