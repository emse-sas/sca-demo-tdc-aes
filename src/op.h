/**
 * @file op.h
 * @author Sami Dahoux (s.dahoux@emse.fr)
 * @brief Module to perform mathematical operations over 32-bit data
 */

#ifndef SCA_FRAMEWORK_OP_H
#define SCA_FRAMEWORK_OP_H

#include <stdint.h>
#include <stdio.h>
#include <math.h>
#include <string.h>

#define OP_HAMMING_TO_ASCII(weight, offset) (weight + 'P' - offset)

/**
 * @brief Computes Hamming weight of the given data
 * @param data 32-bit raw data
 * @return value of the weight
 */
unsigned char OP_hamming_weight(unsigned int data);

/**
 * @brief Computes Hamming distance between the two given data
 * @param left first 32-bit raw data
 * @param right second 32-bit raw data
 * @return value of the distance
 */
unsigned char OP_hamming_distance(unsigned int left, unsigned int right);

/**
 * @brief Computes the Hamming weight of the given words
 * @param words 32-bit values to process
 * @param weights computed weights
 * @param len length of `words`
 */
void OP_words_to_weight(const uint32_t *words, unsigned char *weights, size_t len);


void OP_weights_to_ascii(char* str, uint32_t *weights, size_t len, char offset);

/**
 * @brief Transforms 32-bit registers Hamming weights into a CSV compliant string
 * @param str result string
 * @param weights Hamming weights to stringify
 * @param length of `weights`
 */
void OP_weights_to_string(char* str, uint32_t *weights, size_t len);

int OP_bit_polarity(uint32_t value);

char OP_sum_weights(uint32_t weights, int* coefs);

#endif //SCA_FRAMEWORK_OP_H
