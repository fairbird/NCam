#ifndef MODULE_EMULATOR_ECMDB_H
#define MODULE_EMULATOR_ECMDB_H

#ifdef WITH_EMU

// ECMDB Configuration
#define ECMDB_MAX_CHANNELS      1024
#define ECMDB_MAX_ECM_LEN       256
#define ECMDB_CW_LEN            16
#define ECMDB_HASH_SIZE         8192
#define ECMDB_FILE_CACHE_SIZE   16

// Operation modes
typedef enum {
    ECMDB_MODE_DIRECT = 0,  // File-based lookup (low memory)
    ECMDB_MODE_RAM = 1      // Full in-memory (fast)
} ecmdb_mode_t;

// ECM entry (RAM mode only)
typedef struct ecmdb_entry {
    size_t ecm_offset;
    uint8_t cw[ECMDB_CW_LEN];
    uint16_t ecm_len;
    uint32_t hash;            // xxHash32
    struct ecmdb_entry *next;
} ecmdb_entry_t;

// Channel metadata
typedef struct {
    char *filepath;
    uint16_t caid;
    uint16_t srvid;
    uint8_t ecm_start;
    uint8_t ecm_end;
    uint32_t entry_count;
    
    // RAM mode
    ecmdb_entry_t **hash_table;
    uint8_t *data_pool;
    size_t pool_used;
    size_t pool_size;
} ecmdb_channel_t;

// File cache entry (DIRECT mode)
typedef struct {
    FILE *fp;
    uint32_t channel_idx;
    time_t last_access;
    uint8_t in_use;
} ecmdb_cache_t;

// Main database
typedef struct {
    ecmdb_channel_t *channels;
    uint32_t channel_count;
    uint64_t *lookup_keys;
    ecmdb_mode_t mode;
    ecmdb_cache_t file_cache[ECMDB_FILE_CACHE_SIZE];
    pthread_mutex_t lock;
    uint8_t initialized;
} ecmdb_t;

// Public API
int8_t ecmdb_init(struct s_reader *rdr);
int8_t ecmdb_ecm(uint16_t caid, uint16_t srvid, const uint8_t *ecm, uint8_t *cw);
void ecmdb_cleanup(void);

#endif // WITH_EMU
#endif // MODULE_EMULATOR_ECMDB_H
