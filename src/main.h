
#include <limits.h>
#include <cmd/hex.h>
#include <cmd/run.h>
#include <aes.h>
#include "xparameters.h"
#include "xaes.h"
#include "xfifo.h"
#include "xtdc.h"
#define SCA_PROJECT_VERSION "1.1.0"

XAES aes_inst;
XFIFO fifo_inst;
XTDC tdc_inst;

char buffer[512];
uint32_t key[XAES_WORDS_SIZE], block[XAES_WORDS_SIZE];
uint8_t key8[AES_BLOCKLEN], block8[AES_BLOCKLEN];
struct AES_ctx ctx;

static void AesHwHandler(void *CallBackRef)
{
    XAES_Run(&aes_inst);
}

static void AesSwDecryptHandler(void *CallBackRef)
{
    AES_ECB_decrypt(&ctx, block8);
}

static void AesSwEncryptHandler(void *CallBackRef)
{
    AES_ECB_encrypt(&ctx, block8);
}

char* weights_to_ascii(char *str, uint32_t *weights, size_t len, char offset)
{
    for (size_t t = 0; t < len; t++)
    {
    	if(weights[t] != '\0')
    	{
    		str[t] = weights[t];
    		continue;
    	}
    	str[t] = 1;
    }
    str[len] = '\0';
    return str;
}

char* weights_to_string(char *str, uint32_t *weights, size_t len)
{
    if (len == 0)
    {
        return str;
    }

    char *ptr = str;
    for (size_t t = 0; t < len - 1; t++)
    {
        sprintf(ptr, "%lu,", weights[t]);
        ptr += strlen(ptr);
    }
    sprintf(ptr, "%lu", weights[len - 1]);
    return str;
}

void sum_weights(uint32_t weights[], int a[], uint32_t words, uint32_t len)
{
    uint32_t w0, w1, w2, w3, weight;
    size_t t0, x0;

    for (size_t t = 0; t < len * words; t += words)
    {
        t0 = t / words;
        weight = 0;
        for (size_t w = 0; w < words; w++)
        {
            x0 = t + w;
            w0 = weights[x0] & 0xff;
            w1 = (weights[x0] >> 8) & 0xff;
            w2 = (weights[x0] >> 16) & 0xff;
            w3 = (weights[x0] >> 24) & 0xff;
            if (a == NULL)
            {
                weight += w0 + w1 + w2 + w3;
            }
            else
            {
                weight += a[w] * w0 + a[w + 1] * w1 + a[w + 2] * w2 + a[w + 3] * w3;
            }
        }
        weights[t0] = weight;
    }
}

void sw_aes(int inv, int verbose, int end)
{
    if (verbose)
    {
        printf("mode: sw\n");
        printf("direction: %s\n", inv ? "dec" : "enc");
        printf("key: %s\n", HEX_bytes_to_string(buffer, key8, AES_BLOCKLEN));
        printf("%s: %s\n", inv ? "ciphers" : "plains", HEX_bytes_to_string(buffer, block8, AES_BLOCKLEN));
    }

    if (inv)
    {
        AES_init_ctx_iv(&ctx, key8, block8);
    }
    else
    {
        AES_init_ctx(&ctx, key8);
    }

    fifo_inst.Mode = XFIFO_MODE_SW;
    XFIFO_Reset(&fifo_inst);
    XFIFO_Write(&fifo_inst, end, (XFIFO_WrAction)(inv ? AesSwDecryptHandler : AesSwEncryptHandler));

    printf("%s: %s;;\n", inv ? "plains" : "ciphers", HEX_bytes_to_string(buffer, block8, AES_BLOCKLEN));
}

void hw_aes(int inv, int verbose, int end)
{
    if (verbose)
    {
        printf("mode: hw\n");
        printf("direction: %s\n", inv ? "dec" : "enc");
        printf("keys: %s\n", HEX_words_to_string(buffer, key, XAES_WORDS_SIZE));
        printf("%s: %s\n", inv ? "ciphers" : "plains", HEX_words_to_string(buffer, block, XAES_WORDS_SIZE));
    }

    XAES_Reset(&aes_inst, inv ? XAES_DECRYPT : XAES_ENCRYPT);
    XAES_SetKey(&aes_inst, key);
    XAES_SetInput(&aes_inst, block);

    fifo_inst.Mode = XFIFO_MODE_HW;
    XFIFO_Reset(&fifo_inst);
    XFIFO_Write(&fifo_inst, end, (XFIFO_WrAction)AesHwHandler);

    XAES_GetOutput(&aes_inst, block);
    printf("%s: %s;;\n", inv ? "plains" : "ciphers", HEX_words_to_string(buffer, block, XAES_WORDS_SIZE));
}

CMD_err_t *aes(const CMD_cmd_t *cmd)
{
    int data_idx = CMD_opt_find(cmd->options, 'd');
    int key_idx = CMD_opt_find(cmd->options, 'k');
    int hw = CMD_opt_find(cmd->options, 'h') != -1;
    int inv = CMD_opt_find(cmd->options, 'i') != -1;
    int verbose = CMD_opt_find(cmd->options, 'v') != -1;
    int end = CMD_opt_find(cmd->options, 'e');

    end = end != -1 ? cmd->options[end].value.integer : XFIFO_ConfigTable[0].Depth;

    if (hw)
    {
        HEX_bytes_to_words(key, cmd->options[key_idx].value.bytes, XAES_BYTES_SIZE);
        HEX_bytes_to_words(block, cmd->options[data_idx].value.bytes, XAES_BYTES_SIZE);
        hw_aes(inv, verbose, end);
    }
    else
    {
        memcpy(key8, cmd->options[key_idx].value.bytes, AES_BLOCKLEN);
        memcpy(block8, cmd->options[data_idx].value.bytes, AES_BLOCKLEN);
        sw_aes(inv, verbose, end);
    }
    return NULL;
}

CMD_err_t *tdc(const CMD_cmd_t *cmd)
{
    int calibrate_idx = CMD_opt_find(cmd->options, 'c');
    int raw_idx = CMD_opt_find(cmd->options, 'r');
    int delay_idx = CMD_opt_find(cmd->options, 'd');
    int verbose = CMD_opt_find(cmd->options, 'v') != -1;

    int calibration = calibrate_idx != -1;
    int delay = delay_idx != -1;
    int raw = raw_idx != -1;
    uint64_t current_delay;

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
        printf("value: %08lx ", XTDC_ReadAll(tdc_inst.Config.BaseAddr, 0));
        for (size_t offset = 1; offset < XTDC_ConfigTable[0].CountTdc / 4 ; offset++)
        {
            printf("%08lx ", XTDC_ReadAll(tdc_inst.Config.BaseAddr, offset));
        }
        printf("\n");
    }

    return NULL;
}

void fifo_flush()
{
    XFIFO_Reset(&fifo_inst);
}

void fifo_read(int verbose, int start, int end)
{
    uint32_t words = (XTDC_ConfigTable[0].CountTdc * XTDC_ConfigTable[0].SamplingLen) / 32;
    uint32_t *weights = malloc(32 * (end - start) * words);
    int len = XFIFO_Read(&fifo_inst, weights, (uint32_t)start, (uint32_t)end, words);
    char offset = XTDC_Offset(XTDC_ConfigTable[0].CountTdc, XTDC_ConfigTable[0].SamplingLen);

    sum_weights(weights, NULL, words, len);
    printf("samples: %d;;\n", len);
    if (len == 0)
    {
        return;
    }
    char *str = malloc((verbose ? 4 : 1) * (end - start) * sizeof(char) + 1);
    if (verbose)
    {
        printf("weights: %s;;\n", weights_to_string(str, weights, len));
    }
    else
    {
        printf("code: %s;;\n", weights_to_ascii(str, weights, len, offset));
    }
    free(str);
    free(weights);
}

void fifo_acquire(int end)
{
    fifo_inst.Mode = XFIFO_MODE_SW;
    XFIFO_Reset(&fifo_inst);
    XFIFO_Write(&fifo_inst, end, NULL);
}

CMD_err_t *fifo(const CMD_cmd_t *cmd)
{
    int flush = CMD_opt_find(cmd->options, 'f') != -1;
    int verbose = CMD_opt_find(cmd->options, 'v') != -1;
    int acquire = CMD_opt_find(cmd->options, 'a') != -1;
    int start = CMD_opt_find(cmd->options, 's');
    int end = CMD_opt_find(cmd->options, 'e');

    start = start != -1 ? cmd->options[start].value.integer : 0;
    end = end != -1 ? cmd->options[end].value.integer : XFIFO_ConfigTable[0].Depth;

    if (flush)
    {
        fifo_flush();
    }

    if (acquire)
    {
        fifo_acquire(end);
    }

    fifo_read(verbose, start, end);
    return NULL;
}

CMD_err_t *sca(const CMD_cmd_t *cmd)
{
    int iterations = cmd->options[CMD_opt_find(cmd->options, 't')].value.integer;
    int hw = CMD_opt_find(cmd->options, 'h') != -1;
    int inv = CMD_opt_find(cmd->options, 'i') != -1;
    int verbose = CMD_opt_find(cmd->options, 'v') != -1;
    int raw = CMD_opt_find(cmd->options, 'r') != -1;
    int start = CMD_opt_find(cmd->options, 's');
    int end = CMD_opt_find(cmd->options, 'e');

    HEX_random_words(key, INT_MAX, XAES_WORDS_SIZE);
    HEX_words_to_bytes(key8, key, AES_BLOCKLEN);

    start = start != -1 ? cmd->options[start].value.integer : 0;
    end = end != -1 ? cmd->options[end].value.integer : XFIFO_ConfigTable[0].Depth;

    printf("sensors: %d;;\n", XTDC_ConfigTable[0].CountTdc);
    printf("target: %d;;\n", XTDC_Offset(1, XTDC_ConfigTable[0].SamplingLen));
    printf("mode: %s;;\n", hw ? "hw" : "sw");
    printf("direction: %s;;\n", inv ? "dec" : "enc");
    printf("keys: %s;;\n", HEX_words_to_string(buffer, key, XAES_WORDS_SIZE));

    for (int d = 0; d < iterations; d++)
    {
        if (raw)
        {
            printf("\xfd\xfd\xfd\xfd;;\n");
            fifo_acquire(end);
            fifo_read(verbose, start, end);
        }
        printf("\xfe\xfe\xfe\xfe;;\n");
        HEX_random_words(block, d + 1, XAES_WORDS_SIZE);
        printf("%s: %s;;\n", inv ? "ciphers" : "plains", HEX_words_to_string(buffer, block, XAES_WORDS_SIZE));
        if (hw)
        {
            hw_aes(inv, 0, end);
        }
        else
        {
            HEX_words_to_bytes(block8, block, AES_BLOCKLEN);
            sw_aes(inv, 0, end);
        }
        fifo_read(verbose, start, end);
    }
    fifo_flush();
    printf("\xff\xff\xff\xff;;\n");
    return NULL;
}
