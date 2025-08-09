#define MODULE_LOG_PREFIX "tvcas"
#include "globals.h"

#ifdef WITH_EMU
#include "module-emulator-tvcas.h"
#include "ncam-string.h"
#include <openssl/des.h>
#include <ctype.h>

#define CS_OK    1
#define CS_ERROR 0
#define MASTER_KEY_SIZE 32
#define BLOCK_SIZE 8

static void prepare_3des_key(const uint8_t *key_part, uint8_t *full_key)
{
    memcpy(full_key, key_part, 16);
    memcpy(full_key + 16, key_part, 8);
}

static int32_t decrypt_3des_ecb(const uint8_t *encrypted_data, int32_t data_len,
                                const uint8_t *key_part, uint8_t *decrypted_data)
{
    if (!encrypted_data || !key_part || !decrypted_data || data_len < BLOCK_SIZE)
        return CS_ERROR;

    uint8_t full_key[24];
    prepare_3des_key(key_part, full_key);

    DES_key_schedule ks1, ks2, ks3;
    DES_set_key((DES_cblock *)&full_key[0], &ks1);
    DES_set_key((DES_cblock *)&full_key[8], &ks2);
    DES_set_key((DES_cblock *)&full_key[16], &ks3);

    for (int32_t i = 0; i < data_len; i += BLOCK_SIZE)
    {
        DES_cblock input, output;
        int32_t block_size = (data_len - i < BLOCK_SIZE) ? data_len - i : BLOCK_SIZE;
        
        memset(input, 0, BLOCK_SIZE);
        memcpy(input, encrypted_data + i, block_size);
        
        DES_ecb3_encrypt(&input, &output, &ks1, &ks2, &ks3, DES_DECRYPT);
        memcpy(decrypted_data + i, output, block_size);
    }

    return CS_OK;
}

int32_t ecm_process_master_key(struct s_reader *rdr, const char *key_string)
{
    if (!rdr || !key_string)
        return CS_ERROR;

    char clean_key[65];
    int32_t clean_len = 0;

    for (int32_t i = 0; key_string[i] && clean_len < 64; i++)
    {
        if (isxdigit((unsigned char)key_string[i]))
            clean_key[clean_len++] = toupper((unsigned char)key_string[i]);
    }
    clean_key[clean_len] = '\0';

    if (clean_len != 64)
    {
        cs_log("Invalid master key length: expected 64 hex chars, got %d", clean_len);
        return CS_ERROR;
    }

    for (int32_t i = 0; i < MASTER_KEY_SIZE; i++)
    {
        char hex_pair[3] = {clean_key[i*2], clean_key[i*2+1], '\0'};
        rdr->ecm_master_key[i] = (uint8_t)strtol(hex_pair, NULL, 16);
    }

    rdr->ecm_master_key_length = MASTER_KEY_SIZE;
    cs_log("TVCAS master key loaded successfully");
    return CS_OK;
}

int32_t ecm_decrypt_cw(struct s_reader *rdr, const uint8_t *ecm_data, int32_t ecm_len, uint8_t *cw)
{
    if (!rdr || !ecm_data || !cw || ecm_len < 7 || rdr->ecm_master_key_length != MASTER_KEY_SIZE)
        return CS_ERROR;

    uint8_t table = ecm_data[0];
    const uint8_t *encrypted_payload = ecm_data + 7;
    int32_t payload_len = ecm_len - 7;

    if (payload_len < 20)
    {
        cs_log("TVCAS payload too short: %d bytes", payload_len);
        return CS_ERROR;
    }

    const uint8_t *key_part = (table == 0x81) ? 
                              rdr->ecm_master_key + 16 :
                              rdr->ecm_master_key;

    uint8_t decrypted_data[256];
    if (decrypt_3des_ecb(encrypted_payload, payload_len, key_part, decrypted_data) != CS_OK)
    {
        return CS_ERROR;
    }

    memcpy(cw, decrypted_data + 12, 8);
    memcpy(cw + 8, decrypted_data + 4, 8);

    return CS_OK;
}

#endif
