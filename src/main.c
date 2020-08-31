#include "main.h"

int main(int argc, char *argv[])
{
	printf("\n\n*** cmd_sca %s ***\n\n", SCA_PROJECT_VERSION);

    CMD_err_t *error;
    CMD_descr_tab_t tab = CMD_descr_tab();

    CMD_descr_cmd_t aes_cmd = CMD_descr_cmd("aes", &aes, "AES encryptions.");
    CMD_descr_cmd_t tdc_cmd = CMD_descr_cmd("tdc", &tdc, "TDC sensor setting and read.");
    CMD_descr_cmd_t fifo_cmd = CMD_descr_cmd("fifo", &fifo, "FIFO setting, read and flush.");
    CMD_descr_cmd_t sca_cmd = CMD_descr_cmd("sca", &sca, "AES Side-channel FIFO acquisition.");

    CMD_descr_push_opt(&aes_cmd, CMD_descr_opt('v', CMD_OPT_NONE, 1, "Verbose output."));
    CMD_descr_push_opt(&aes_cmd, CMD_descr_opt('h', CMD_OPT_NONE, 1, "Perform hardware AES."));
    CMD_descr_push_opt(&aes_cmd, CMD_descr_opt('i', CMD_OPT_NONE, 1, "Perform inverse AES encryption."));
    CMD_descr_push_opt(&aes_cmd, CMD_descr_opt('a', CMD_OPT_NONE, 1, "Perform FIFO acquisition during AES."));
    CMD_descr_push_opt(&aes_cmd, CMD_descr_opt('k', CMD_OPT_BYTES, 0, "AES key block."));
    CMD_descr_push_opt(&aes_cmd, CMD_descr_opt('d', CMD_OPT_BYTES, 0, "AES data block."));

    CMD_descr_push_opt(&tdc_cmd, CMD_descr_opt('v', CMD_OPT_NONE, 1, "Verbose output."));
    CMD_descr_push_opt(&tdc_cmd, CMD_descr_opt('r', CMD_OPT_INT, 1, "Read raw TDC sensors value."));
    CMD_descr_push_opt(&tdc_cmd, CMD_descr_opt('c', CMD_OPT_INT, 1, "Perform automatic calibration."));
    CMD_descr_push_opt(&tdc_cmd, CMD_descr_opt('d', CMD_OPT_INT, 1, "Perform manual calibration."));

    CMD_descr_push_opt(&fifo_cmd, CMD_descr_opt('v', CMD_OPT_NONE, 1, "Verbose output."));
    CMD_descr_push_opt(&fifo_cmd, CMD_descr_opt('f', CMD_OPT_NONE, 1, "Flush the FIFO."));

    CMD_descr_push_opt(&sca_cmd, CMD_descr_opt('v', CMD_OPT_NONE, 1, "Verbose output."));
    CMD_descr_push_opt(&sca_cmd, CMD_descr_opt('h', CMD_OPT_NONE, 1, "Perform hardware AES."));
    CMD_descr_push_opt(&sca_cmd, CMD_descr_opt('i', CMD_OPT_NONE, 1, "Perform inverse AES encryption."));
    CMD_descr_push_opt(&sca_cmd, CMD_descr_opt('t', CMD_OPT_INT, 0, "Count of AES iterations."));

    CMD_descr_push_cmd(&tab, aes_cmd);
    CMD_descr_push_cmd(&tab, tdc_cmd);
    CMD_descr_push_cmd(&tab, fifo_cmd);
    CMD_descr_push_cmd(&tab, sca_cmd);


    XAES_CfgInitialize(&aes_inst, &XAES_ConfigTable[0]);

    XFIFO_CfgInitialize(&fifo_inst, &XFIFO_ConfigTable[0]);

    XTDC_CfgInitialize(&tdc_inst, &XTDC_ConfigTable[0]);
    XTDC_Calibrate(&tdc_inst, 0, 0);

    if ((error = CMD_run(&tab)) != NULL)
    {
        fprintf(stderr, "%s\n", error->message);
        free(error);
        return 1;
    }
    return 0;
}
