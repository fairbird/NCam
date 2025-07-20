#define MODULE_LOG_PREFIX "tvcas"
#include "globals.h"

#ifdef WITH_EMU
#include "module-emulator-tvcas.h"
#include "ncam-string.h"
#include <openssl/des.h>
#include <ctype.h>

#define CS_OK    1
#define CS_ERROR 0

static void ecm_prepare_3des_key(const uint8_t *key_part, uint8_t *full_key);
static int32_t ecm_decrypt_3des_ecb(const uint8_t *encrypted_data, int32_t data_len,
const uint8_t *key_part, uint8_t *decrypted_data);

static void ecm_prepare_3des_key(const uint8_t *key_part, uint8_t *full_key)
{
    if (!key_part || !full_key)
    {
        cs_log("Invalid parameters for key preparation");
        return;
    }

    memcpy(full_key, key_part, 16);
    memcpy(full_key + 16, key_part, 8);

    char tmp[65];
    cs_log_dbg(D_TRACE, "3DES Key prepared from 16-byte key_part");
    cs_log_dbg(D_TRACE, "Key part (16 bytes): %s",
    cs_hexdump(1, key_part, 16, tmp, sizeof(tmp)));
    cs_log_dbg(D_TRACE, "Full 3DES key (24 bytes): %s",
    cs_hexdump(1, full_key, 24, tmp, sizeof(tmp)));
}

static int32_t ecm_decrypt_3des_ecb(const uint8_t *encrypted_data, int32_t data_len,
const uint8_t *key_part, uint8_t *decrypted_data)
{
    if (!encrypted_data || !key_part || !decrypted_data || data_len < 8)
    {
        cs_log("Invalid parameters for 3DES decryption");
        return CS_ERROR;
    }

    cs_log_dbg(D_TRACE, "Starting 3DES decryption for %d bytes", data_len);

    uint8_t full_key[24];
    ecm_prepare_3des_key(key_part, full_key);

    DES_key_schedule ks1, ks2, ks3;

    DES_cblock *key1 = (DES_cblock *)&full_key[0];
    DES_cblock *key2 = (DES_cblock *)&full_key[8];
    DES_cblock *key3 = (DES_cblock *)&full_key[16];

    int key1_result = DES_set_key_checked(key1, &ks1);
    int key2_result = DES_set_key_checked(key2, &ks2);
    int key3_result = DES_set_key_checked(key3, &ks3);

    cs_log_dbg(D_TRACE, "DES_set_key_checked results: K1=%d, K2=%d, K3=%d",
    key1_result, key2_result, key3_result);

    if (key1_result != 0 || key2_result != 0 || key3_result != 0)
    {
        cs_log_dbg(D_TRACE, "Trying DES_set_key instead of DES_set_key_checked");
        DES_set_key(key1, &ks1);
        DES_set_key(key2, &ks2);
        DES_set_key(key3, &ks3);
        cs_log_dbg(D_TRACE, "Using DES_set_key (no error checking)");
    }

    cs_log_dbg(D_TRACE, "3DES keys set successfully");

    int32_t blocks_processed = 0;
    for (int32_t i = 0; i < data_len; i += 8)
    {
        DES_cblock input, output;
        int32_t block_size = (data_len - i < 8) ? data_len - i : 8;

        memset(input, 0, 8);
        memcpy(input, encrypted_data + i, block_size);

        DES_ecb3_encrypt(&input, &output, &ks1, &ks2, &ks3, DES_DECRYPT);

        memcpy(decrypted_data + i, output, block_size);
        blocks_processed++;

        if (blocks_processed <= 3)
        {
            char tmp[65];
            cs_log_dbg(D_TRACE, "Block %d - Input: %s",
            blocks_processed, cs_hexdump(1, input, 8, tmp, sizeof(tmp)));
            cs_log_dbg(D_TRACE, "Block %d - Output: %s",
            blocks_processed, cs_hexdump(1, output, 8, tmp, sizeof(tmp)));
        }
    }

    cs_log_dbg(D_TRACE, "3DES decryption completed - %d blocks processed", blocks_processed);

    return CS_OK;
}

int32_t ecm_process_master_key(struct s_reader *rdr, const char *key_string)
{
    if (!rdr || !key_string)
    {
        cs_log("Invalid parameters for master key processing");
        return CS_ERROR;
    }

    cs_log_dbg(D_TRACE, "Processing master key from config");

    char clean_key[65];
    int32_t clean_len = 0;

    for (int32_t i = 0; key_string[i] && clean_len < 64; i++)
    {
        unsigned char c = (unsigned char)key_string[i];
        if (isxdigit(c))
        {
            clean_key[clean_len++] = toupper(c);
        }
    }
    clean_key[clean_len] = '\0';

    if (clean_len != 64)
    {
        cs_log("Invalid master key length - expected 64 hex characters, got %d", clean_len);
        return CS_ERROR;
    }

    for (int32_t i = 0; i < 32; i++)
    {
        char hex_pair[3] = {clean_key[i*2], clean_key[i*2+1], '\0'};
        rdr->ecm_master_key[i] = (uint8_t)strtol(hex_pair, NULL, 16);
    }

    rdr->ecm_master_key_length = 32;

    cs_log("Master key loaded successfully (32 bytes)");

    char tmp[65];
    cs_log("K1 (Even): %s", cs_hexdump(1, rdr->ecm_master_key, 16, tmp, sizeof(tmp)));
    cs_log("K2 (Odd):  %s", cs_hexdump(1, rdr->ecm_master_key + 16, 16, tmp, sizeof(tmp)));

    return CS_OK;
}

int32_t ecm_decrypt_cw(struct s_reader *rdr, const uint8_t *ecm_data, int32_t ecm_len, uint8_t *cw)
{
    if (!rdr || !ecm_data || !cw || ecm_len < 7)
    {
        cs_log("Invalid parameters for ECM decryption");
        return CS_ERROR;
    }

    if (rdr->ecm_master_key_length != 32)
    {
        cs_log_dbg(D_TRACE, "Master key not configured properly (length: %d)",
        rdr->ecm_master_key_length);
        return CS_ERROR;
    }

    uint8_t table = ecm_data[0];
    const uint8_t *encrypted_payload = ecm_data + 7;
    int32_t payload_len = ecm_len - 7;

    cs_log("Table ID: 0x%02X, Payload length: %d bytes", table, payload_len);

    if (payload_len < 20)
    {
        cs_log("Encrypted payload too short (%d bytes, minimum 20 required)", payload_len);
        return CS_ERROR;
    }

    const uint8_t *key_part;
    const char *key_name;

    if (table == 0x81)
    {
        key_part = rdr->ecm_master_key + 16;
        key_name = "K2 (Odd table)";
    }
    else
    {
        key_part = rdr->ecm_master_key;
        key_name = "K1 (Even table)";
    }

    cs_log_dbg(D_TRACE, "Using %s for table 0x%02X", key_name, table);

    char tmp[65];
    cs_log_dbg(D_TRACE, "Selected key part (16 bytes): %s",
    cs_hexdump(1, key_part, 16, tmp, sizeof(tmp)));
    cs_log_dbg(D_TRACE, "Encrypted payload: %s",
    cs_hexdump(1, encrypted_payload, payload_len > 32 ? 32 : payload_len, tmp, sizeof(tmp)));

    uint8_t decrypted_data[256];
    if (ecm_decrypt_3des_ecb(encrypted_payload, payload_len, key_part, decrypted_data) != CS_OK)
    {
        cs_log("3DES decryption failed");
        return CS_ERROR;
    }

    cs_log_dbg(D_TRACE, "Decrypted data: %s",
    cs_hexdump(1, decrypted_data, payload_len > 32 ? 32 : payload_len, tmp, sizeof(tmp)));

    if (payload_len < 20)
    {
        cs_log("Decrypted payload too short for CW extraction");
        return CS_ERROR;
    }

    uint8_t cw1[8], cw2[8];
    memcpy(cw1, decrypted_data + 4, 8);
    memcpy(cw2, decrypted_data + 12, 8);

    cs_log_dbg(D_TRACE, "CW1 extracted: %s", cs_hexdump(1, cw1, 8, tmp, sizeof(tmp)));
    cs_log_dbg(D_TRACE, "CW2 extracted: %s", cs_hexdump(1, cw2, 8, tmp, sizeof(tmp)));

    memcpy(cw, cw2, 8);
    memcpy(cw + 8, cw1, 8);

    return CS_OK;
}

#endif