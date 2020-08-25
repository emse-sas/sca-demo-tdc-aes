#include "tdc_hw.h"

uint32_t TDC_HW_read(int id, TDC_HW_mode_t mode)
{
    uint32_t data;
    switch (mode)
    {
    case TDC_HW_MODE_WEIGHT:
        data = Xil_In32(TDC_HW_ADDR(TDC_HW_WEIGHTS_POS_0));
        return id != -1 ? TDC_HW_WEIGHT(data, id) : data;
    case TDC_HW_MODE_RAW:
        Xil_Out32(TDC_HW_ADDR(TDC_HW_SEL_POS), id);
        return Xil_In32(TDC_HW_ADDR(TDC_HW_RAW_POS));
    case TDC_HW_MODE_SUM:
        return Xil_In32(TDC_HW_ADDR(TDC_HW_SUM_POS));
    }
}

void TDC_HW_write_delay(uint32_t fine, uint32_t coarse, int id)
{
    if (id == -1)
    {
        Xil_Out32(TDC_HW_ADDR(TDC_HW_FINE_POS), fine);
        Xil_Out32(TDC_HW_ADDR(TDC_HW_COARSE_POS), coarse);
        return;
    }
    uint32_t current_fine = Xil_In32(TDC_HW_ADDR(TDC_HW_FINE_POS));
    uint32_t current_coarse = Xil_In32(TDC_HW_ADDR(TDC_HW_COARSE_POS));
    Xil_Out32(TDC_HW_ADDR(TDC_HW_FINE_POS), (current_fine & TDC_HW_FINE_MASK(id)) | (fine << (4 * id)));
    Xil_Out32(TDC_HW_ADDR(TDC_HW_COARSE_POS), (current_coarse & TDC_HW_COARSE_MASK(id)) | (coarse << (2 * id)));
}

uint64_t TDC_HW_read_delay(int id)
{
    uint64_t fine = Xil_In32(TDC_HW_ADDR(TDC_HW_FINE_POS));
    uint64_t coarse = Xil_In32(TDC_HW_ADDR(TDC_HW_COARSE_POS));
    if (id == -1)
    {
        return TDC_HW_DELAY_64(fine, coarse);
    }
    fine = (fine & ~TDC_HW_FINE_MASK(id)) >> (4 * id);
    coarse = (coarse & ~TDC_HW_COARSE_MASK(id)) >> (2 * id);
    return TDC_HW_DELAY_64(fine, coarse);
}

uint64_t TDC_HW_calibrate(int iterations, int verbose)
{
    iterations = iterations ? iterations : TDC_HW_DEFAULT_CALIBRATE_IT;
    uint32_t best_fine = 0, best_coarse = 0;
    uint32_t value, best_value, raw;
    uint32_t target = TDC_HW_CALIBRATE_TARGET * iterations;
    int polarity;

    TDC_HW_write_delay(0, 0, -1);
    for (int id = 0; id < TDC_HW_COUNT_TDC; id++)
    {
        if (verbose)
        {
            printf("device: %d\n\r", id);
        }
        best_value = UINT32_MAX;
        for (uint32_t coarse = 0; coarse <= TDC_HW_COARSE_MAX; coarse++)
        {
            for (uint32_t fine = 0; fine <= TDC_HW_FINE_MAX; fine++)
            {
                value = 0;
                polarity = 0;
                TDC_HW_write_delay(fine, coarse, id);
                for (int i = 0; i < iterations; i++)
                {
                    raw = TDC_HW_read(id, TDC_HW_MODE_RAW);
                    value += OP_hamming_weight(raw);
                    polarity += OP_bit_polarity(raw);
                }
                if (verbose)
                {
                    printf("(%lx, %lx): %5.2f (p: %5.2f)\n\r", fine, coarse, (float)value / iterations, (float)polarity / iterations);
                }
                if (abs(target - value) < abs(target - best_value) && polarity > -iterations / 2)
                {
                    best_value = value;
                    best_fine = fine;
                    best_coarse = coarse;
                }
            }
        }
        TDC_HW_write_delay(best_fine, best_coarse, id);
    }
    return TDC_HW_read_delay(-1);
}
