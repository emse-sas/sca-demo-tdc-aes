
#include <limits.h>
#include <cmd/hex.h>
#include <cmd/run.h>
#include "op.h"
#include <aes.h>
#include "xparameters.h"
#include "xaes.h"
#include "xfifo.h"
#include "xtdc.h"
#define SCA_PROJECT_VERSION "1.1.0"

#define XFIFO_STACK_SIZE 8192

XAES aes_inst;
XFIFO fifo_inst;
XTDC tdc_inst;

void tiny_aes(uint8_t *block, const uint8_t *key, int inv, int acq, int verbose)
{
    struct AES_ctx ctx;
    char buffer[9 * AES_BLOCKLEN + 3];

    if (verbose)
    {
        printf("mode: sw\n");
        printf("direction: %s\n", inv ? "decrypt" : "encrypt");
        printf("key: %s\n", HEX_bytes_to_string(buffer, key, AES_BLOCKLEN));
        printf("%s: %s\n", inv ? "cipher" : "plain", HEX_bytes_to_string(buffer, block, AES_BLOCKLEN));
    }

    if (inv)
    {
        AES_init_ctx_iv(&ctx, key, block);
    }
    else
    {
        AES_init_ctx(&ctx, key);
    }

    if (acq && inv)
    {
        XFIFO_Reset(&fifo_inst, XFIFO_MODE_SW);
        XFIFO_StartWrite(fifo_inst.Config.BaseAddr);
        AES_ECB_decrypt(&ctx, block);
        XFIFO_StopWrite(fifo_inst.Config.BaseAddr);
    }
    else if (acq && !inv)
    {
        XFIFO_Reset(&fifo_inst, XFIFO_MODE_SW);
        XFIFO_StartWrite(fifo_inst.Config.BaseAddr);
        AES_ECB_encrypt(&ctx, block);
        XFIFO_StopWrite(fifo_inst.Config.BaseAddr);
    }
    else if (!acq && inv)
    {
        AES_ECB_decrypt(&ctx, block);
    }
    else
    {
        AES_ECB_encrypt(&ctx, block);
    }
    printf("%s: %s\n", inv ? "plain" : "cipher", HEX_bytes_to_string(buffer, block, AES_BLOCKLEN));
}

void hw_aes(uint32_t *block, const uint32_t *key, int inv, int acq, int verbose)
{
    char block_str[9 * XAES_BYTES_SIZE + 3], key_str[9 * XAES_BYTES_SIZE + 3];

    if (verbose)
    {
        printf("mode: hw\n");
        printf("direction: %s\n", inv ? "decrypt" : "encrypt");
        printf("key: %s\n", HEX_words_to_string(key_str, key, XAES_WORDS_SIZE));
        printf("%s: %s\n", inv ? "cipher" : "plain", HEX_words_to_string(block_str, block, XAES_WORDS_SIZE));
    }

    XAES_Reset(&aes_inst, inv ? XAES_DECRYPT : XAES_ENCRYPT);
    XAES_SetKey(&aes_inst, key);
    XAES_SetInput(&aes_inst, block);
    if (acq)
    {
        XFIFO_Reset(&fifo_inst, XFIFO_MODE_HW);
        XFIFO_StartWrite(fifo_inst.Config.BaseAddr);
        XAES_Run(&aes_inst);
        XFIFO_StopWrite(fifo_inst.Config.BaseAddr);
    }
    else
    {
        XAES_Run(&aes_inst);
    }

    XAES_GetOutput(&aes_inst, block);
    printf("%s: %s\n", inv ? "plain" : "cipher", HEX_words_to_string(block_str, block, XAES_WORDS_SIZE));
}

CMD_err_t *aes(const CMD_cmd_t *cmd)
{
    int data_idx = CMD_opt_find(cmd->options, 'd');
    int key_idx = CMD_opt_find(cmd->options, 'k');
    int hw = CMD_opt_find(cmd->options, 'h') != -1;
    int acq = CMD_opt_find(cmd->options, 'a') != -1;
    int inv = CMD_opt_find(cmd->options, 'i') != -1;
    int verbose = CMD_opt_find(cmd->options, 'v') != -1;

    if (hw)
    {
        uint32_t key[XAES_WORDS_SIZE], block[XAES_WORDS_SIZE];
        HEX_bytes_to_words(key, cmd->options[key_idx].value.bytes, XAES_BYTES_SIZE);
        HEX_bytes_to_words(block, cmd->options[data_idx].value.bytes, XAES_BYTES_SIZE);
        hw_aes(block, key, inv, acq, verbose);
    }
    else
    {
        uint8_t key[AES_BLOCKLEN], block[AES_BLOCKLEN];
        memcpy(key, cmd->options[key_idx].value.bytes, AES_BLOCKLEN);
        memcpy(block, cmd->options[data_idx].value.bytes, AES_BLOCKLEN);
        tiny_aes(block, key, inv, acq, verbose);
    }
    return NULL;
}

CMD_err_t *tdc(const CMD_cmd_t *cmd)
{
    int calibrate_idx = CMD_opt_find(cmd->options, 'c');
    int raw_idx = CMD_opt_find(cmd->options, 'r');
    int delay_idx = CMD_opt_find(cmd->options, 'd');
    int verbose = CMD_opt_find(cmd->options, 'v') != -1;

    uint64_t current_delay;
    int calibration = calibrate_idx != -1;
    int delay = delay_idx != -1;
    int raw = raw_idx != -1;

    if (delay)
    {
        XTDC_WriteDelay(&tdc_inst, -1, cmd->options[delay_idx].value.words[0], cmd->options[delay_idx].value.words[1]);
    }

    if (calibration)
    {
        XTDC_Calibrate(&tdc_inst, cmd->options[calibrate_idx].value.integer, verbose);
    }

    if (verbose || calibration)
    {
        current_delay = XTDC_ReadDelay(&tdc_inst, -1);
        printf("delay: 0x%08x%08x\n", (unsigned int)(current_delay >> 32), (unsigned int)current_delay);
    }

    if (raw)
    {
        int id = cmd->options[raw_idx].value.integer;
        XTDC_SetId(tdc_inst.Config.BaseAddr, id);
        printf("raw %d: %08lx\n", id, XTDC_ReadRaw(tdc_inst.Config.BaseAddr));
        return NULL;
    }
    else
    {
        printf("value: %08lx\n", XTDC_ReadWeight(tdc_inst.Config.BaseAddr, -1));
    }

    return NULL;
}

void fifo_flush()
{
    XFIFO_Reset(&fifo_inst, XFIFO_MODE_SW);
}

void fifo_read(int verbose)
{
    uint32_t weights[XFIFO_STACK_SIZE];
    int len = XFIFO_Read(&fifo_inst, weights, XFIFO_STACK_SIZE);

    for (size_t i = 0; i < len; i++)
    {
        weights[i] = OP_sum_weights(weights[i], NULL);
    }

    printf("samples: %d\n", len);
    if (len == 0)
    {
        return;
    }
    if (verbose)
    {
        char str[4 * XFIFO_STACK_SIZE + 16] = "";
        OP_weights_to_string(str, weights, len);
        printf("weights: %s\n", str);
    }
    else
    {
        char str[XFIFO_STACK_SIZE + 16] = "";
        OP_weights_to_ascii(str, weights, len, XTDC_ConfigTable[0].CountTdc * XTDC_ConfigTable[0].SamplingLen * 2);
        printf("code: %s\n", str);
    }
}

CMD_err_t *fifo(const CMD_cmd_t *cmd)
{
    int flush = CMD_opt_find(cmd->options, 'f') != -1;
    int verbose = CMD_opt_find(cmd->options, 'v') != -1;

    if (flush != -1)
    {
        fifo_flush();
    }

    fifo_read(verbose);

    return NULL;
}

CMD_err_t *sca(const CMD_cmd_t *cmd)
{
    int traces_idx = CMD_opt_find(cmd->options, 't');
    int hw = CMD_opt_find(cmd->options, 'h') != -1;
    int inv = CMD_opt_find(cmd->options, 'i') != -1;
    int verbose = CMD_opt_find(cmd->options, 'v') != -1;
    int iterations = cmd->options[traces_idx].value.integer;
    char buffer[9 * AES_BLOCKLEN + 3];
    uint32_t key[XAES_WORDS_SIZE], block[XAES_WORDS_SIZE];
    uint8_t key8[AES_BLOCKLEN], block8[AES_BLOCKLEN];

    HEX_random_words(key, INT_MAX, XAES_WORDS_SIZE);
    HEX_words_to_bytes(key8, key, AES_BLOCKLEN);

    printf("sensors: %d\n", XTDC_ConfigTable[0].CountTdc);
    printf("target: %d\n", XTDC_ConfigTable[0].SamplingLen * 2);
    printf("mode: %s\n", hw ? "hw" : "sw");
    printf("direction: %s\n", inv ? "decrypt" : "encrypt");
    printf("key: %s\n", HEX_words_to_string(buffer, key, XAES_WORDS_SIZE));
    for (int idx = 0; idx < iterations; idx++)
    {
        printf("\xfe\xfe\xfe\xfe\n");
        HEX_random_words(block, idx + 1, XAES_WORDS_SIZE);
        printf("%s: %s\n", inv ? "cipher" : "plain", HEX_words_to_string(buffer, block, XAES_WORDS_SIZE));
        if (hw)
        {
            hw_aes(block, key, inv, 1, 0);
        }
        else
        {
            HEX_words_to_bytes(block8, block, AES_BLOCKLEN);
            tiny_aes(block8, key8, inv, 1, 0);
        }
        fifo_read(verbose);
    }
    printf("\xff\xff\xff\xff\n");
    return NULL;
}
