/**
 * @file fifo_hw.h
 * @author Sami Dahoux (s.dahoux@emse.fr)
 * @brief Driver for the FIFO controller IP contained in the test system vivado_sca
 * 
 * The FIFO controller performs asymmetric operations on a FIFO :
 * - pushes values from a hardware device
 * - pops values into the CPU
 * 
 * Pushes can only be initiated and stopped by this software. 
 * The value are added to the FIFO at a sampling rate that depends on the hardware and the addition stops when the FIFO is full.
 * 
 * Pops can be initiated and stopped by this software.
 * The popped values can be read via the corresponding API.
 */

#ifndef SCA_FRAMEWORK_FIFO_HW_H
#define SCA_FRAMEWORK_FIFO_HW_H

#include <unistd.h>
#include "xparameters.h"
#include "xil_io.h"
#include "aes_hw.h"

#define FIFO_HW_WORD_SIZE 4

#define FIFO_HW_BASE_ADDR XPAR_FIFO_CONTROLLER_0_S_AXI_BASEADDR

#define FIFO_HW_DATA_POS 0
#define FIFO_HW_STATUS_POS_RD 1
#define FIFO_HW_STATUS_POS_WR 2

#define FIFO_HW_STATUS_EMPTY 1
#define FIFO_HW_STATUS_FULL 2

#define FIFO_HW_STATUS_NULL 0
#define FIFO_HW_STATUS_RESET 1
#define FIFO_HW_STATUS_READ 2
#define FIFO_HW_STATUS_WRITE 4
#define FIFO_HW_STATUS_MODE 8

#define FIFO_HW_ADDR(pos) (FIFO_HW_BASE_ADDR + FIFO_HW_WORD_SIZE * pos)
#define FIFO_HW_STATUS_SET_1(status, status_reg) (status_reg | status)
#define FIFO_HW_STATUS_SET_0(status, status_reg) (status_reg & ~status)
#define FIFO_HW_STATUS_GET(status, status_reg) (status_reg & status)

#define FIFO_HW_STACK_SIZE 8192 /** Data size of the FIFO stack */

typedef enum {
    FIFO_HW_MODE_HW = FIFO_HW_STATUS_MODE,
    FIFO_HW_MODE_SW = FIFO_HW_STATUS_NULL
} FIFO_HW_mode_t;

/**
 * @brief Checks if the FIFO is empty
 * @return 1 if the FIFO is empty 0 otherwise
 */
int FIFO_HW_is_empty();


/**
 * @brief Checks if the FIFO is full
 * @return 1 if the FIFO is full 0 otherwise
 */
int FIFO_HW_is_full();

/**
 * @brief Set read status signal to 1 into the hardware
 */
void FIFO_HW_start_read();

/**
 * @brief Set read status signal to 0 into the hardware
 */
void FIFO_HW_stop_read();

/*
 * @brief Set the write status signal to 1
 */
void FIFO_HW_start_write();

/*
 * @brief Set the write status signal to 0
 */
void FIFO_HW_stop_write();

/**
 * @brief Flushes the FIFO
 */
void FIFO_HW_clear(FIFO_HW_mode_t mode);

/*
 * @brief Pops a single value from the FIFO
 */
uint32_t FIFO_HW_pop();

/**
 * @brief Pops all the values contained in the FIFO
 * 
 * @param words buffer for contained values
 * @param len count of elements in the buffer
 * @return number of elements read until the FIFO is empty or `FIFO_HW_ERR_NONE`
 */
int FIFO_HW_read(uint32_t *words, size_t len);

typedef enum
{
    FIFO_HW_ERR_NONE = -1,
    FIFO_HW_ERR_FULL = -2,
    FIFO_HW_ERR_EMPTY = -3
} FIFO_HW_err_t;

#endif
