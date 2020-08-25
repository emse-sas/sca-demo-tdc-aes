/**
 * @file aes_hw.h
 * @author Sami Dahoux (s.dahoux@emse.fr)
 * @brief Driver for the AES IP contained in the test system vivado_sca
 * 
 * In all the following contents, a block refers to a 16-words array or a 4-words array, which is the data format for the AES algorithm.
 * The driver API allows encryption and decryption, therefore, the input/ouput refers to either plain or the cipher raw hexadecimal data.
 */

#ifndef SCA_FRAMEWORK_AES_HW_H
#define SCA_FRAMEWORK_AES_HW_H

#include <stdint.h>
#include <unistd.h>
#include "xparameters.h"
#include "xil_io.h"

#define AES_HW_WORDS_SIZE 4
#define AES_HW_BYTES_SIZE 16

#define AES_HW_BASE_ADDR XPAR_SIMPLE_AES_0_S_AXI_BASEADDR

#define AES_HW_DATA_POS_IN_0 0
#define AES_HW_DATA_POS_IN_1 1
#define AES_HW_DATA_POS_IN_2 2
#define AES_HW_DATA_POS_IN_3 3

#define AES_HW_DATA_POS_OUT_0 4
#define AES_HW_DATA_POS_OUT_1 5
#define AES_HW_DATA_POS_OUT_2 6
#define AES_HW_DATA_POS_OUT_3 7

#define AES_HW_DATA_POS_KEY_0 8
#define AES_HW_DATA_POS_KEY_1 9
#define AES_HW_DATA_POS_KEY_2 10
#define AES_HW_DATA_POS_KEY_3 11

#define AES_HW_STATUS_POS_IN 12
#define AES_HW_STATUS_POS_OUT 13

#define AES_HW_STATUS_NULL 0

#define AES_HW_STATUS_START 2
#define AES_HW_STATUS_RESET 1
#define AES_HW_STATUS_INV 4

#define AES_HW_STATUS_DONE 1

#define AES_HW_ADDR(pos) (AES_HW_BASE_ADDR + AES_HW_WORDS_SIZE * pos)
#define AES_HW_STATUS_SET_1(status, status_reg) (status_reg | status)
#define AES_HW_STATUS_SET_0(status, status_reg) (status_reg & ~status)
#define AES_HW_STATUS_GET(status, status_reg) (status_reg & status)

typedef enum {
    AES_HW_ENCRYPT = AES_HW_STATUS_NULL,
    AES_HW_DECRYPT = AES_HW_STATUS_INV
} AES_HW_mode_t;

/**
 * @brief Resets the hardware device and set the encryption mode
 * @param mode set encryption or decryption
 */
void AES_HW_clear(AES_HW_mode_t mode);

/**
 * @brief Writes input block data
 * @param words input block words
 */
void AES_HW_write_input(const uint32_t *words);

/**
 * @brief Writes key block data
 * @param words key block words
 */
void AES_HW_write_key(const uint32_t *words);

/**
 * @brief Reads input block data
 * @param words input block words
 */
void AES_HW_read_input(uint32_t *words);

/**
 * @brief Reads key block data
 * @param words key block words
 */
void AES_HW_read_key(uint32_t *words);

/**
 * @brief Reads outpout block data
 * @param words output block words
 */
void AES_HW_read_output(uint32_t *words);

/**
 * @brief Starts hardware AES computing and wait until done
 */
void AES_HW_launch();

#endif //SCA_FRAMEWORK_AES_HW_H
