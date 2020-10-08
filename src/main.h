
#include <limits.h>
#include <cmd/hex.h>
#include <cmd/run.h>
#include <tiny-AES-c/aes.h>
#include <openssl/aes.h>
#include "xparameters.h"
#include "xaes.h"
#include "xfifo.h"
// #include "xro.h"
#include "xtdc.h"
#define SCA_PROJECT_VERSION "1.1.0"

XAES aes_inst;
XFIFO fifo_inst;
XTDC tdc_inst;
// XRO ro_inst;

char buffer[512];
uint32_t key_hw[XAES_WORDS_SIZE], block_hw[XAES_WORDS_SIZE];
uint8_t key_tiny[AES_BLOCKLEN], block_tiny[AES_BLOCKLEN];
unsigned char in_ssl[AES_BLOCK_SIZE], out_ssl[AES_BLOCK_SIZE], key_ssl[AES_BLOCK_SIZE];
AES_KEY key32_ssl;

struct AES_ctx ctx_tiny;

int seed = 1;

static void AesHwHandler(void *CallBackRef)
{
    XAES_Run(&aes_inst);
}

static void AesTinyDecryptHandler(void *CallBackRef)
{
    AES_ECB_decrypt(&ctx_tiny, block_tiny);
}

static void AesTinyEncryptHandler(void *CallBackRef)
{
    AES_ECB_encrypt(&ctx_tiny, block_tiny);
}

static void AesSslDecryptHandler(void *CallBackRef)
{
    AES_decrypt(in_ssl, out_ssl, &key32_ssl);
}

static void AesSslEncryptHandler(void *CallBackRef)
{
    AES_encrypt(in_ssl, out_ssl, &key32_ssl);
}

char *weights_to_ascii(char *str, uint32_t *weights, size_t len, char offset)
{
    for (size_t t = 0; t < len; t++)
    {
        if (weights[t] > 255)
        {
            str[t] = 255;
            continue;
        }

        str[t] = weights[t];
        if (str[t] == '\0' || str[t] == '\n' || str[t] == '\r')
        {
            str[t]++;
        }
    }
    str[len] = '\0';
    return str;
}

char *weights_to_string(char *str, uint32_t *weights, size_t len)
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

void tiny_aes(int inv, int verbose, int end)
{
    if (verbose)
    {
        printf("mode: tiny\n");
        printf("direction: %s\n", inv ? "dec" : "enc");
        printf("key: %s\n", HEX_bytes_to_string(buffer, key_tiny, AES_BLOCKLEN));
        printf("%s: %s\n", inv ? "ciphers" : "plains", HEX_bytes_to_string(buffer, block_tiny, AES_BLOCKLEN));
    }

    if (inv)
    {
        AES_init_ctx_iv(&ctx_tiny, key_tiny, block_tiny);
    }
    else
    {
        AES_init_ctx(&ctx_tiny, key_tiny);
    }

    fifo_inst.Mode = XFIFO_MODE_SW;
    XFIFO_Reset(&fifo_inst);
    XFIFO_Write(&fifo_inst, end, (XFIFO_WrAction)(inv ? AesTinyDecryptHandler : AesTinyEncryptHandler));

    printf("%s: %s;;\n", inv ? "plains" : "ciphers", HEX_bytes_to_string(buffer, block_tiny, AES_BLOCKLEN));
}

void ssl_aes(int inv, int verbose, int end)
{
    if (verbose)
    {
        printf("mode: ssl\n");
        printf("direction: %s\n", inv ? "dec" : "enc");
        printf("key: %s\n", HEX_words_to_string(buffer, key_ssl, 4));
        printf("%s: %s\n", inv ? "ciphers" : "plains", HEX_bytes_to_string(buffer, in_ssl, AES_BLOCK_SIZE));
    }

    if (inv)
    {
        AES_set_decrypt_key(key_ssl, 128, &key32_ssl);
    }
    else
    {
        AES_set_encrypt_key(key_ssl, 128, &key32_ssl);
    }

    fifo_inst.Mode = XFIFO_MODE_SW;
    XFIFO_Reset(&fifo_inst);
    XFIFO_Write(&fifo_inst, end, (XFIFO_WrAction)(inv ? AesSslDecryptHandler : AesSslEncryptHandler));

    printf("%s: %s;;\n", inv ? "plains" : "ciphers", HEX_bytes_to_string(buffer, out_ssl, AES_BLOCK_SIZE));
}

void hw_aes(int inv, int verbose, int end)
{
    if (verbose)
    {
        printf("mode: hw\n");
        printf("direction: %s\n", inv ? "dec" : "enc");
        printf("keys: %s\n", HEX_words_to_string(buffer, key_hw, XAES_WORDS_SIZE));
        printf("%s: %s\n", inv ? "ciphers" : "plains", HEX_words_to_string(buffer, block_hw, XAES_WORDS_SIZE));
    }

    XAES_Reset(&aes_inst, inv ? XAES_DECRYPT : XAES_ENCRYPT);
    XAES_SetKey(&aes_inst, key_hw);
    XAES_SetInput(&aes_inst, block_hw);

    fifo_inst.Mode = XFIFO_MODE_HW;
    XFIFO_Reset(&fifo_inst);
    XFIFO_Write(&fifo_inst, end, (XFIFO_WrAction)AesHwHandler);

    XAES_GetOutput(&aes_inst, block_hw);
    printf("%s: %s;;\n", inv ? "plains" : "ciphers", HEX_words_to_string(buffer, block_hw, XAES_WORDS_SIZE));
}

CMD_err_t *aes(const CMD_cmd_t *cmd)
{
    int data_idx = CMD_opt_find(cmd->options, 'd');
    int key_idx = CMD_opt_find(cmd->options, 'k');
    int mode_idx = CMD_opt_find(cmd->options, 'm');
    int inv = CMD_opt_find(cmd->options, 'i') != -1;
    int verbose = CMD_opt_find(cmd->options, 'v') != -1;
    int end = CMD_opt_find(cmd->options, 'e');
    char *mode = cmd->options[mode_idx].value.string;

    end = end != -1 ? cmd->options[end].value.integer : XFIFO_ConfigTable[0].Depth;

    if (!strcmp(mode, "hw"))
    {
        HEX_bytes_to_words(key_hw, cmd->options[key_idx].value.bytes, XAES_BYTES_SIZE);
        HEX_bytes_to_words(block_hw, cmd->options[data_idx].value.bytes, XAES_BYTES_SIZE);
        hw_aes(inv, verbose, end);
    }
    else if (!strcmp(mode, "tiny"))
    {
        memcpy(key_tiny, cmd->options[key_idx].value.bytes, AES_BLOCKLEN);
        memcpy(block_tiny, cmd->options[data_idx].value.bytes, AES_BLOCKLEN);
        tiny_aes(inv, verbose, end);
    }
    else if (!strcmp(mode, "ssl"))
    {
        memcpy(key_ssl, cmd->options[key_idx].value.bytes, AES_BLOCK_SIZE);
        memcpy(in_ssl, cmd->options[data_idx].value.bytes, AES_BLOCK_SIZE);
        ssl_aes(inv, verbose, end);
    }
    else
    {
        printf("unrecognized encryption mode: %s", mode);
    }
    return NULL;
}

CMD_err_t *tdc(const CMD_cmd_t *cmd)
{
    int calibrate_idx = CMD_opt_find(cmd->options, 'c');
    int state_idx = CMD_opt_find(cmd->options, 's');
    int delay_idx = CMD_opt_find(cmd->options, 'd');
    int verbose = CMD_opt_find(cmd->options, 'v') != -1;

    int calibration = calibrate_idx != -1;
    int delay = delay_idx != -1;
    int state = state_idx != -1;
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

    if (state)
    {
        int id = cmd->options[state_idx].value.integer;
        XTDC_SetId(tdc_inst.Config.BaseAddr, id);
        printf("state %d: %08lx\n", id, XTDC_ReadState(tdc_inst.Config.BaseAddr));
        return NULL;
    }
    else
    {
        printf("data: %ld\n", XTDC_ReadData(tdc_inst.Config.BaseAddr));
    }

    return NULL;
}
/*
CMD_err_t *ro(const CMD_cmd_t *cmd)
{
    int raw_idx = CMD_opt_find(cmd->options, 'r');
    int verbose = CMD_opt_find(cmd->options, 'v') != -1;
    int raw = raw_idx != -1;

    if (raw)
    {
        int id = cmd->options[raw_idx].value.integer;
        XRO_SetId(ro_inst.Config.BaseAddr, id);
        printf("state %d: %08lx\n", id, XRO_ReadState(ro_inst.Config.BaseAddr));
        return NULL;
    }
    else
    {
        printf("value: %08lx\n", XRO_Read(ro_inst.Config.BaseAddr));
    }

    return NULL;
}
*/

void fifo_flush()
{
    XFIFO_Reset(&fifo_inst);
}

void fifo_read(int verbose, int start, int end)
{
    uint32_t *weights = malloc(32 * (end - start));
    int len = XFIFO_Read(&fifo_inst, weights, (uint32_t)start, (uint32_t)end, 1);
    char offset = XTDC_Offset(XTDC_ConfigTable[0].Count, XTDC_ConfigTable[0].Depth);

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
    int inv = CMD_opt_find(cmd->options, 'i') != -1;
    int verbose = CMD_opt_find(cmd->options, 'v') != -1;
    int raw = CMD_opt_find(cmd->options, 'r') != -1;
    int mode_idx = CMD_opt_find(cmd->options, 'm');
    int start = CMD_opt_find(cmd->options, 's');
    int end = CMD_opt_find(cmd->options, 'e');
    char *mode = cmd->options[mode_idx].value.string;

    HEX_random_words(key_hw, INT_MAX, XAES_WORDS_SIZE);
    HEX_words_to_bytes(key_tiny, key_hw, AES_BLOCKLEN);
    memcpy(key_ssl, key_hw, AES_BLOCK_SIZE);

    start = start != -1 ? cmd->options[start].value.integer : 0;
    end = end != -1 ? cmd->options[end].value.integer : XFIFO_ConfigTable[0].Depth;

    printf("sensors: %d;;\n", XTDC_ConfigTable[0].Count);
    printf("target: %d;;\n", XTDC_Offset(1, XTDC_ConfigTable[0].Depth));
    printf("mode: %s;;\n", mode);
    printf("direction: %s;;\n", inv ? "dec" : "enc");
    printf("keys: %s;;\n", HEX_words_to_string(buffer, key_hw, XAES_WORDS_SIZE));

    for (int d = 0; d < iterations; d++)
    {
        if (raw)
        {
            printf("\xfd\xfd\xfd\xfd;;\n");
            fifo_acquire(end);
            fifo_read(verbose, start, end);
        }
        printf("\xfe\xfe\xfe\xfe;;\n");
        HEX_random_words(block_hw, seed, XAES_WORDS_SIZE);
        printf("%s: %s;;\n", inv ? "ciphers" : "plains", HEX_words_to_string(buffer, block_hw, XAES_WORDS_SIZE));
        if (!strcmp(mode, "hw"))
        {
            hw_aes(inv, verbose, end);
        }
        else if (!strcmp(mode, "tiny"))
        {
            HEX_words_to_bytes(block_tiny, block_hw, AES_BLOCKLEN);
            tiny_aes(inv, verbose, end);
        }
        else if (!strcmp(mode, "ssl"))
        {
            memcpy(in_ssl, block_hw, AES_BLOCK_SIZE);
            ssl_aes(inv, verbose, end);
        }
        else
        {
            printf("unrecognized encryption mode: %s", mode);
        }
        fifo_read(verbose, start, end);
        seed++;
    }
    fifo_flush();
    printf("\xff\xff\xff\xff;;\n");
    return NULL;
}
