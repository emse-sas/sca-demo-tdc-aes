//
// Created by Sami Dahoux (s.dahoux@emse.fr) on 19/06/2020.
//

#include "op.h"

const static unsigned int bit_shift = 1;

unsigned char OP_hamming_weight(unsigned int data)
{
    unsigned int weight = 0;
    for (; data > 0; data >>= bit_shift)
    {
        weight += data & bit_shift;
    }
    return weight;
}

unsigned char OP_hamming_distance(unsigned int left, unsigned int right)
{
    unsigned int bit_diff = left ^ right;
    unsigned int weight = 0;
    for (; bit_diff > 0; bit_diff >>= bit_shift)
    {
        weight += bit_diff & bit_shift;
    }
    return weight;
}

int OP_bit_polarity(uint32_t value)
{

    if (value == UINT32_MAX || value == 0)
    {
        return -1;
    }

    int polarity = ((value & 0x1) == 0);
    for (; value > 0; value >>= bit_shift)
    {
        if (((value & 0x1) == 0) != polarity)
        {
            return -2;
        }
    }
    return polarity;
}

void OP_words_to_weight(const uint32_t *words, unsigned char *weights, size_t len)
{
    for (size_t idx = 0; idx < len; idx++)
    {
        weights[idx] = OP_hamming_weight(words[idx]);
    }
}

void OP_weights_to_ascii(char *str, uint32_t *weights, size_t len, char offset)
{
    for (size_t idx = 0; idx < len; idx++)
    {
        str[idx] = OP_HAMMING_TO_ASCII(weights[idx], offset);
    }
    str[len] = '\0';
}

void OP_weights_to_string(char *str, uint32_t *weights, size_t len)
{
    if (len == 0)
    {
        return;
    }

    char *ptr = str;
    for (size_t idx = 0; idx < len - 1; idx++)
    {
        sprintf(ptr, "%lu,", weights[idx]);
        ptr += strlen(ptr);
    }
    sprintf(ptr, "%lu", weights[len - 1]);
}

char OP_sum_weights(uint32_t weights, int *coefs)
{
    char buffer[] = {weights & 0xff, (weights >> 8) & 0xff, (weights >> 16) & 0xff, (weights >> 24) & 0xff};
    if (coefs == NULL)
    {
        return buffer[0] + buffer[1] + buffer[2] + buffer[3];
    }
    return coefs[0] * buffer[0] + coefs[1] * buffer[1] + coefs[2] * buffer[2] + coefs[3] * buffer[3];
}
