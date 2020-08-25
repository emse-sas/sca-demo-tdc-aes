/**
 * @file tdc_hw.h
 * @author Sami Dahoux (s.dahoux@emse.fr)
 * @brief Driver for the TDC IP contained in the test system vivado_sca
 * 
 * According to the hardware configuration, only the first data words will be filt with acquisition value. The remaining bits will contain 0.
 */

#ifndef SCA_FRAMEWORK_TDC_HW_H
#define SCA_FRAMEWORK_TDC_HW_H

#include "xparameters.h"
#include "xil_io.h"
#include "op.h"
#include <stdint.h>
#include <stdlib.h>

#define TDC_HW_WORD_SIZE 4
#define TDC_HW_COUNT_TDC 4
#define TDC_HW_BASE_ADDR XPAR_TDC_BANK_0_S_AXI_BASEADDR

#define TDC_HW_WEIGHTS_POS_0 0
#define TDC_HW_WEIGHTS_POS_1 1
#define TDC_HW_RAW_POS 2
#define TDC_HW_SUM_POS 3
#define TDC_HW_FINE_POS 4
#define TDC_HW_COARSE_POS 5
#define TDC_HW_SEL_POS 6
#define TDC_HW_ADDR(pos) (TDC_HW_BASE_ADDR + TDC_HW_WORD_SIZE * pos)

#define TDC_HW_DEFAULT_CALIBRATE_IT 8192
#define TDC_HW_CALIBRATE_TARGET 16
#define TDC_HW_COARSE_MAX 0x3
#define TDC_HW_FINE_MAX 0xf

#define TDC_HW_DELAY_64(fine, coarse) ((uint64_t) ((coarse << 32) | (fine & 0xffffffff)))
#define TDC_HW_FINE_MASK(id) ((uint32_t) ((0xfffffff0 << (4 * id)) | (0x0ffffff >> (4 * (4 - id + 2)))))
#define TDC_HW_COARSE_MASK(id) ((uint32_t) ((0xfffffffc << (2 * id)) | (0xcffffff >> (2 * (4 - id + 8)))))
#define TDC_HW_DATA_MASK(id) ((uint32_t) ((0xffffff00 << (8 * id)) | (0x00ffffff >> (8 * (4 - id - 1)))))
#define TDC_HW_WEIGHT(data, id) ((uint32_t) ((data &  ~TDC_HW_DATA_MASK(id)) >> (8 * id)))


typedef enum {
    TDC_HW_MODE_RAW,
    TDC_HW_MODE_WEIGHT,
    TDC_HW_MODE_SUM
} TDC_HW_mode_t;

/**
 * @brief Reads the current value of the TDC data registers
 * @return read value
 */
uint32_t TDC_HW_read(int id, TDC_HW_mode_t mode);

/**
 * @brief Writes the given value of the delay into the corresponding register
 */
void TDC_HW_write_delay(uint32_t fine, uint32_t coarse, int id);

uint64_t TDC_HW_read_delay(int id);

/**
 * @brief Calibrates the TDC in order to provide the best range and sensitivity
 * 
 * The calibration tests all the delay tunning values and pick the best according to measurement.
 * For each delay tunning, an average on `iterations` acquired values is performed.
 * Depending on the value of the average the delay setting is saved or not.
 *   
 * @param iterations count of samples for average
 * @param true to display calibration log
 * @return chosen calibration delay value
 */
uint64_t TDC_HW_calibrate(int iterations, int verbose);

#endif //SCA_FRAMEWORK_TDC_HW_H
