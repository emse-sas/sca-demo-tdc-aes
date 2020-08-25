#include "aes_hw.h"

void AES_HW_clear(AES_HW_mode_t mode)
{
    Xil_Out32(
        AES_HW_ADDR(AES_HW_STATUS_POS_IN),
        AES_HW_STATUS_SET_1(AES_HW_STATUS_RESET, mode));
    usleep(1);
    Xil_Out32(
        AES_HW_ADDR(AES_HW_STATUS_POS_IN),
        AES_HW_STATUS_SET_0(AES_HW_STATUS_RESET, Xil_In32(AES_HW_ADDR(AES_HW_STATUS_POS_IN))));
}

void AES_HW_write_input(const uint32_t *words)
{
    Xil_Out32(AES_HW_ADDR(AES_HW_DATA_POS_IN_0), words[0]);
    Xil_Out32(AES_HW_ADDR(AES_HW_DATA_POS_IN_1), words[1]);
    Xil_Out32(AES_HW_ADDR(AES_HW_DATA_POS_IN_2), words[2]);
    Xil_Out32(AES_HW_ADDR(AES_HW_DATA_POS_IN_3), words[3]);
}

void AES_HW_write_key(const uint32_t *words)
{
    Xil_Out32(AES_HW_ADDR(AES_HW_DATA_POS_KEY_0), words[0]);
    Xil_Out32(AES_HW_ADDR(AES_HW_DATA_POS_KEY_1), words[1]);
    Xil_Out32(AES_HW_ADDR(AES_HW_DATA_POS_KEY_2), words[2]);
    Xil_Out32(AES_HW_ADDR(AES_HW_DATA_POS_KEY_3), words[3]);
}

void AES_HW_read_input(uint32_t *words)
{
    words[0] = Xil_In32(AES_HW_ADDR(AES_HW_DATA_POS_IN_0));
    words[1] = Xil_In32(AES_HW_ADDR(AES_HW_DATA_POS_IN_1));
    words[2] = Xil_In32(AES_HW_ADDR(AES_HW_DATA_POS_IN_2));
    words[3] = Xil_In32(AES_HW_ADDR(AES_HW_DATA_POS_IN_3));
}

void AES_HW_read_key(uint32_t *words)
{
    words[0] = Xil_In32(AES_HW_ADDR(AES_HW_DATA_POS_KEY_0));
    words[1] = Xil_In32(AES_HW_ADDR(AES_HW_DATA_POS_KEY_1));
    words[2] = Xil_In32(AES_HW_ADDR(AES_HW_DATA_POS_KEY_2));
    words[3] = Xil_In32(AES_HW_ADDR(AES_HW_DATA_POS_KEY_3));
}

void AES_HW_read_output(uint32_t *words)
{
    words[0] = Xil_In32(AES_HW_ADDR(AES_HW_DATA_POS_OUT_0));
    words[1] = Xil_In32(AES_HW_ADDR(AES_HW_DATA_POS_OUT_1));
    words[2] = Xil_In32(AES_HW_ADDR(AES_HW_DATA_POS_OUT_2));
    words[3] = Xil_In32(AES_HW_ADDR(AES_HW_DATA_POS_OUT_3));
}

void AES_HW_launch()
{
    Xil_Out32(
        AES_HW_ADDR(AES_HW_STATUS_POS_IN),
        AES_HW_STATUS_SET_1(AES_HW_STATUS_START, Xil_In32(AES_HW_ADDR(AES_HW_STATUS_POS_IN))));
    while (!AES_HW_STATUS_GET(AES_HW_STATUS_DONE, Xil_In32(AES_HW_ADDR(AES_HW_STATUS_POS_OUT))))
    {
    }
    Xil_Out32(
        AES_HW_ADDR(AES_HW_STATUS_POS_IN),
        AES_HW_STATUS_SET_0(AES_HW_STATUS_START, Xil_In32(AES_HW_ADDR(AES_HW_STATUS_POS_IN))));
}
