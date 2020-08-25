
#include <limits.h>
#include <cmd/hex.h>
#include <cmd/run.h>
#include "../tiny-AES-c/aes.h"
#include "aes_hw.h"
#include "tdc_hw.h"
#include "fifo_hw.h"

#define SCA_PROJECT_VERSION "1.1.0"

void tiny_aes(uint8_t *block, const uint8_t *key, int inv, int acq)
{
    struct AES_ctx ctx;
    char block_str[9 * AES_BLOCKLEN + 3], key_str[9 * AES_BLOCKLEN + 3];

    printf("key: %s\n", HEX_bytes_to_string(key_str, key, AES_BLOCKLEN));
    printf("%s: %s\n", inv ? "cipher" : "plain", HEX_bytes_to_string(block_str, block, AES_BLOCKLEN));
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
        FIFO_HW_clear(FIFO_HW_MODE_SW);
        FIFO_HW_start_write();
        AES_ECB_decrypt(&ctx, block);
        FIFO_HW_stop_write();
    }
    else if (acq && !inv)
    {
        FIFO_HW_clear(FIFO_HW_MODE_SW);
        FIFO_HW_start_write();
        AES_ECB_encrypt(&ctx, block);
        FIFO_HW_stop_write();
    }
    else if (!acq && inv)
    {
        AES_ECB_decrypt(&ctx, block);
    }
    else
    {
        AES_ECB_encrypt(&ctx, block);
    }
    printf("%s: %s\n", inv ? "plain" : "cipher", HEX_bytes_to_string(block_str, block, AES_BLOCKLEN));
}

void hw_aes(uint32_t *block, const uint32_t *key, int inv, int acq)
{
    char block_str[9 * AES_HW_BYTES_SIZE + 3], key_str[9 * AES_HW_BYTES_SIZE + 3];

    printf("key: %s\n", HEX_words_to_string(key_str, key, AES_HW_WORDS_SIZE));
    printf("%s: %s\n", inv ? "cipher" : "plain", HEX_words_to_string(block_str, block, AES_HW_WORDS_SIZE));
    AES_HW_clear(inv ? AES_HW_DECRYPT : AES_HW_ENCRYPT);
    AES_HW_write_key(key);
    AES_HW_write_input(block);
    if (acq)
    {
        FIFO_HW_clear(FIFO_HW_MODE_HW);
        FIFO_HW_start_write();
        AES_HW_launch();
        FIFO_HW_stop_write();
    }
    else
    {
        AES_HW_launch();
    }

    AES_HW_read_output(block);
    printf("%s: %s\n", inv ? "plain" : "cipher", HEX_words_to_string(block_str, block, AES_HW_WORDS_SIZE));
}

CMD_err_t *aes(const CMD_cmd_t *cmd)
{
    int data_idx = CMD_opt_find(cmd->options, 'd');
    int key_idx = CMD_opt_find(cmd->options, 'k');
    int hw = CMD_opt_find(cmd->options, 'h') != -1;
    int acq = CMD_opt_find(cmd->options, 'a') != -1;
    int inv = CMD_opt_find(cmd->options, 'i') != -1;

    if (hw)
    {
        uint32_t key[AES_HW_WORDS_SIZE], block[AES_HW_WORDS_SIZE];
        HEX_bytes_to_words(key, cmd->options[key_idx].value.bytes, AES_HW_BYTES_SIZE);
        HEX_bytes_to_words(block, cmd->options[data_idx].value.bytes, AES_HW_BYTES_SIZE);
        hw_aes(block, key, inv, acq);
    }
    else
    {
        uint8_t key[AES_BLOCKLEN], block[AES_BLOCKLEN];
        memcpy(key, cmd->options[key_idx].value.bytes, AES_BLOCKLEN);
        memcpy(block, cmd->options[data_idx].value.bytes, AES_BLOCKLEN);
        tiny_aes(block, key, inv, acq);
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
        TDC_HW_write_delay(cmd->options[delay_idx].value.words[0], cmd->options[delay_idx].value.words[1], -1);
        current_delay = TDC_HW_read_delay(-1);
    }

    if (calibration)
    {
        current_delay = TDC_HW_calibrate(cmd->options[calibrate_idx].value.integer, verbose);
    }

    if (verbose || calibration)
    {
        printf("delay: 0x%08x%08x\n", (unsigned int)(current_delay >> 32), (unsigned int)current_delay);
    }

    if (raw)
    {
        int id = cmd->options[raw_idx].value.integer;
        printf("raw %d: %08lx\n", id, TDC_HW_read(id, TDC_HW_MODE_RAW));
        return NULL;
    }
    else
    {
        printf("value: %08lx\n", TDC_HW_read(-1, TDC_HW_MODE_WEIGHT));
    }

    return NULL;
}

void fifo_flush()
{
    FIFO_HW_clear(FIFO_HW_MODE_SW);
}

void fifo_read(int verbose)
{
    uint32_t weights[FIFO_HW_STACK_SIZE];
    int len = FIFO_HW_read(weights, FIFO_HW_STACK_SIZE);

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
        char str[4 * FIFO_HW_STACK_SIZE + 16] = "";
        OP_weights_to_string(str, weights, len);
        printf("weights: %s\n", str);
    }
    else
    {
        char str[FIFO_HW_STACK_SIZE + 16] = "";
        OP_weights_to_ascii(str, weights, len, TDC_HW_CALIBRATE_TARGET * TDC_HW_COUNT_TDC);
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
    uint32_t key[AES_HW_WORDS_SIZE], block[AES_HW_WORDS_SIZE];
    uint8_t key8[AES_BLOCKLEN], block8[AES_BLOCKLEN];

    printf("mode: %s\n", hw ? "hw" : "sw");
    printf("direction: %s\n", inv ? "decrypt" : "encrypt");
    printf("sensors: %d\n", TDC_HW_COUNT_TDC);
    printf("target: %d\n", TDC_HW_CALIBRATE_TARGET);

    HEX_random_words(key, INT_MAX, AES_HW_WORDS_SIZE);
    HEX_words_to_bytes(key8, key, AES_BLOCKLEN);
    for (int idx = 0; idx < iterations; idx++)
    {
        printf("\xfe\xfe\xfe\xfe\n");
        HEX_random_words(block, idx + 1, AES_HW_WORDS_SIZE);
        if (hw)
        {
            hw_aes(block, key, inv, 1);
        }
        else
        {
            HEX_words_to_bytes(block8, block, AES_BLOCKLEN);
            tiny_aes(block8, key8, inv, 1);
        }
        fifo_read(verbose);
    }
    printf("\xff\xff\xff\xff\n");
    return NULL;
}
