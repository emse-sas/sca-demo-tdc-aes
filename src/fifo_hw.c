#include "fifo_hw.h"

int FIFO_HW_is_empty()
{
    return FIFO_HW_STATUS_GET(FIFO_HW_STATUS_EMPTY, Xil_In32(FIFO_HW_ADDR(FIFO_HW_STATUS_POS_RD)));
}

int FIFO_HW_is_full()
{
    return FIFO_HW_STATUS_GET(FIFO_HW_STATUS_FULL, Xil_In32(FIFO_HW_ADDR(FIFO_HW_STATUS_POS_RD)));
}

void FIFO_HW_start_read()
{
    Xil_Out32(
        FIFO_HW_ADDR(FIFO_HW_STATUS_POS_WR),
        FIFO_HW_STATUS_SET_1(FIFO_HW_STATUS_READ, Xil_In32(FIFO_HW_ADDR(FIFO_HW_STATUS_POS_WR))));
}

void FIFO_HW_stop_read()
{
    Xil_Out32(
        FIFO_HW_ADDR(FIFO_HW_STATUS_POS_WR),
        FIFO_HW_STATUS_SET_0(FIFO_HW_STATUS_READ, Xil_In32(FIFO_HW_ADDR(FIFO_HW_STATUS_POS_WR))));
}

void FIFO_HW_start_write()
{
    Xil_Out32(
        FIFO_HW_ADDR(FIFO_HW_STATUS_POS_WR),
        FIFO_HW_STATUS_SET_1(FIFO_HW_STATUS_WRITE, Xil_In32(FIFO_HW_ADDR(FIFO_HW_STATUS_POS_WR))));
}

void FIFO_HW_stop_write()
{
    Xil_Out32(
        FIFO_HW_ADDR(FIFO_HW_STATUS_POS_WR),
        FIFO_HW_STATUS_SET_0(FIFO_HW_STATUS_WRITE, Xil_In32(FIFO_HW_ADDR(FIFO_HW_STATUS_POS_WR))));
}

void FIFO_HW_clear(FIFO_HW_mode_t mode)
{
    Xil_Out32(
        FIFO_HW_ADDR(FIFO_HW_STATUS_POS_WR),
        FIFO_HW_STATUS_SET_1(FIFO_HW_STATUS_RESET, mode));
    usleep(1);
    Xil_Out32(
        FIFO_HW_ADDR(FIFO_HW_STATUS_POS_WR),
        FIFO_HW_STATUS_SET_0(FIFO_HW_STATUS_RESET, Xil_In32(FIFO_HW_ADDR(FIFO_HW_STATUS_POS_WR))));
}

uint32_t FIFO_HW_pop()
 {
    FIFO_HW_start_read();
    uint32_t value = Xil_In32(FIFO_HW_ADDR(FIFO_HW_DATA_POS));
    FIFO_HW_stop_read();
    return value;
}

int FIFO_HW_read(uint32_t *words, size_t len)
{
	size_t idx = 0;
    for (;idx < len && !FIFO_HW_is_empty(); idx++)
    {
        words[idx] = FIFO_HW_pop();
    }
    return idx;
}
