#define MODULE_LOG_PREFIX "emu"
#include "globals.h"

#ifdef WITH_EMU

#include "cscrypt/des.h"
#include "module-emulator-nemu.h"

int8_t conax_ecm(uint16_t caid, uint8_t *ecm, uint8_t *dw)
{
	if(SCT_LEN(ecm) != 0x37 || ecm[5] != 0x64)
	{
		return EMU_NOT_SUPPORTED;
	}

	uint8_t key[16];
	if(!emu_find_key('C', caid, 0, ecm[0] == 0x80 ? "00" : "01", key, 16, 1, 0, 0, NULL))
	{
		return EMU_KEY_NOT_FOUND;
	}

	uint32_t ks1[32], ks2[32];
	des_set_key(&key[0], ks1);
	des_set_key(&key[8], ks2);

	int32_t i;
	for(i = 7; i < 24; i += 8)
	{
		des(&ecm[i], ks1, 0);
		des(&ecm[i], ks2, 1);
		des(&ecm[i], ks1, 0);
	}

	memcpy(&dw[8], &ecm[11], 8);
	memcpy(&dw[0], &ecm[19], 8);
#if 0
	return EMU_OK;
#else
	return (is_valid_dcw(dw) && is_valid_dcw(dw + 8)) ? EMU_OK : EMU_CHECKSUM_ERROR;
#endif
}

#endif
