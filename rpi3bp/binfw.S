.section ".binfw"

        .global bin_fw_start
bin_fw_start:
        .incbin "bootfip0.bin"

        .global bin_fw_end
bin_fw_end: