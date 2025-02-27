#define OUT_TRIG 1

#if OUT_TRIG
/*     itewqq start: custom gpio operations       */
#define GPIO_COUNT 5
// 40 on the board, GPIO3_B3 = 32*3 + 8*1 + 3 = 107
#define TRIGGER_PIN 106

typedef union {
    struct {
        volatile int L;
        volatile int H;
    };
    volatile int reg[2];
} Pair;

// 来自 RK3588 手册
typedef volatile struct {
    Pair SWPORT_DR;      // 0x0000: 数据寄存器
    Pair SWPORT_DDR;     // 0x0008: 方向寄存器
    Pair INT_EN;         // 0x0010: 中断使能
    Pair INT_MASK;       // 0x0018: 中断屏蔽
    Pair INT_TYPE;       // 0x0020: 中断类型
    Pair INT_POLARITY;   // 0x0028: 中断极性
    Pair INT_BOTHEDGE;   // 0x0030: 中断双边沿触发
    Pair DEBOUNCE;       // 0x0038: 去抖动寄存器
    Pair DBCLK_DIV_EN;   // 0x0040: 去抖动时钟使能
    int  DBCLK_DIV_CON;  // 0x0048: 去抖动时钟配置
    int  _pad0;          // 0x004C: 保留，填充 4 字节
    int  INT_STATUS;     // 0x0050: 中断状态
    int  _pad1;          // 0x0054: 保留
    int  INT_RAWSTATUS;  // 0x0058: 原始中断状态
    int  _pad2;          // 0x005C: 保留
    Pair PORT_EOI;       // 0x0060: 中断结束寄存器
    int  EXT_PORT;       // 0x0070: 外部端口输入寄存器
    int  _pad3;          // 0x0074: 保留
    int  VER_ID;         // 0x0078: 版本号
    int  _pad4[33];      // 0x007C - 0x00FF: 填充 132 字节（33*4）
    Pair GPIO_REG_GROUP; // 0x0100: GPIO 分组寄存器
    int  VIRTUAL_EN;     // 0x0108: 虚拟使能寄存器
} GpioRegisters;

typedef struct {
    GpioRegisters* gpios[GPIO_COUNT];
} Rk3588Gpio;

static int rk3588gpio_read(Rk3588Gpio *gpio, int pin) {
#if defined(__aarch64__) || defined(_M_ARM64)
    int group = pin / 32;
    int bit = pin & 31;
    return (gpio->gpios[group]->EXT_PORT & (1 << bit)) != 0;
#endif
}

static void rk3588gpio_write(Rk3588Gpio *gpio, int pin, int value) {
#if defined(__aarch64__) || defined(_M_ARM64)
    int group = pin / 32;
    int high = ((pin & 31) > 15); // 低 16 位使用 SWPORT_DR.L，高 16 位使用 SWPORT_DR.H
    int indx = pin & 15;
    // 根据 RK3588 手册，写入时将高 16 位设为掩码位，低 16 位为值（0xFFFF 表示置高，0x0000 表示置低）
    int mask = (1 << (16 + indx)) | (value ? 0xFFFF : 0x0000);
    if (high)
        gpio->gpios[group]->SWPORT_DR.H = mask;
    else
        gpio->gpios[group]->SWPORT_DR.L = mask;
#endif
}

static void rk3588gpio_set_output(Rk3588Gpio *gpio, int pin, int is_output) {
#if defined(__aarch64__) || defined(_M_ARM64)
    int group = pin / 32;
    int high = ((pin & 31) > 15); // 同上，低16位与高16位分别对应
    int indx = pin & 15;
    int mask = (1 << (16 + indx)) | (is_output ? 0xFFFF : 0x0000);
    if (high)
        gpio->gpios[group]->SWPORT_DDR.H = mask;
    else
        gpio->gpios[group]->SWPORT_DDR.L = mask;
#endif
}
Rk3588Gpio Gpio = {{ (GpioRegisters *)0xFD8A0000, (GpioRegisters *)0xFEC20000, (GpioRegisters *)0xFEC30000, (GpioRegisters *)0xFEC40000, (GpioRegisters *)0xFEC50000 }};

/*     itewqq end: custom gpio operations       */
#endif


#if OUT_TRIG // itewqq start
	// Rk3588Gpio Gpio = {{ (GpioRegisters *)0xFD8A0000, (GpioRegisters *)0xFEC20000, (GpioRegisters *)0xFEC30000, (GpioRegisters *)0xFEC40000, (GpioRegisters *)0xFEC50000 }};
#if defined(__aarch64__) || defined(_M_ARM64)
	// printf("itewqq: we are here!\n");
#endif
	rk3588gpio_set_output(&Gpio, TRIGGER_PIN, 1); // set to ouput 
	rk3588gpio_write(&Gpio, TRIGGER_PIN, 0); // pull down
#endif // itewqq end