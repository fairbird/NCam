#define MODULE_LOG_PREFIX "emu"
#include "globals.h"

#ifdef WITH_EMU

#include "cscrypt/des.h"
#include "module-emulator-nemu.h"
#include "ncam-string.h"

int8_t conax_ecm(uint16_t caid, uint8_t *ecm, uint8_t *dw)
{
	uint32_t i, ks1[32], ks2[32];
	uint8_t key[16], keyIndex = ecm[0] & 3, ecm_len = ecm[4] - 2, nano = ecm[5], *ecm_data = ecm + 7;

	/* TVCAS3 test ... */
	if(ecm_len != 48 || nano != 0x64)
	{
		return EMU_NOT_SUPPORTED;
	}

	if(!emu_find_key('C', caid, 0, keyIndex ? "01" : "00", key, 16, 0, 0, 0, NULL))
	{
		cs_log("Key not found: C %04X %02X", caid, keyIndex);
		return EMU_KEY_NOT_FOUND;
	}

	cs_log_dbg(D_ATR | D_READER, "CAID: %04X, Key index: %02X, Nano: %02X, ECM len: %d", caid, keyIndex, nano, ecm_len);
	//char tmp[16 * 2 + 1];
	//cs_log_dbg(D_ATR | D_READER, "Found key: C %04X %02X %s", caid, keyIndex, cs_hexdump(0, key, 16, tmp, sizeof(tmp)));

	des_set_key(key, ks1);
	des_set_key(key + 8, ks2);

	cs_log_dump_dbg(D_ATR | D_READER, ecm_data, 24, "Encrypted ECM segment:");

	for(i = 0; i < 17; i += 8)
	{
		des(ecm_data + i, ks1, 0);
		des(ecm_data + i, ks2, 1);
		des(ecm_data + i, ks1, 0);
	}

	cs_log_dump_dbg(D_ATR | D_READER, ecm_data, 24, "Decrypted ECM segment:");

	memcpy(dw + 8, ecm_data + 4, 8);
	memcpy(dw, ecm_data + 12, 8);

	cs_log_dump_dbg(D_ATR | D_READER, dw, 16, "Control Word:");
#if 0
	return EMU_OK;
#else
	return (is_valid_dcw(dw) && is_valid_dcw(dw + 8)) ? EMU_OK : EMU_CHECKSUM_ERROR;
#endif
}

#endif
