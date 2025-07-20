#ifndef MODULE_EMULATOR_TVCAS_H
#define MODULE_EMULATOR_TVCAS_H

#ifdef WITH_EMU

#include "globals.h"

int32_t ecm_decrypt_cw(struct s_reader *rdr, const uint8_t *ecm_data, int32_t ecm_len, uint8_t *cw);
int32_t ecm_process_master_key(struct s_reader *rdr, const char *key_string);

#endif
#endif