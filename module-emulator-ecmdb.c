#define MODULE_LOG_PREFIX "emu"

#include "globals.h"

#ifdef WITH_EMU

#include "ncam-string.h"
#include "module-emulator-nemu.h"
#include "module-emulator-ecmdb.h"

static ecmdb_t *ecmdb = NULL;

// xxHash32 Implementation (inline, optimized)
#define XXH_PRIME32_1  0x9E3779B1U
#define XXH_PRIME32_2  0x85EBCA77U
#define XXH_PRIME32_3  0xC2B2AE3DU
#define XXH_PRIME32_4  0x27D4EB2FU
#define XXH_PRIME32_5  0x165667B1U

static inline uint32_t xxh_rotl32(uint32_t x, int r)
{
    return (x << r) | (x >> (32 - r));
}

static inline uint32_t xxh_read32(const void *ptr)
{
    uint32_t val;
    memcpy(&val, ptr, sizeof(val));
    return val;
}

static uint32_t xxhash32(const uint8_t *data, size_t len, uint32_t seed)
{
    const uint8_t *p = data;
    const uint8_t *end = data + len;
    uint32_t h32;
    
    if (len >= 16)
    {
        const uint8_t *limit = end - 16;
        uint32_t v1 = seed + XXH_PRIME32_1 + XXH_PRIME32_2;
        uint32_t v2 = seed + XXH_PRIME32_2;
        uint32_t v3 = seed;
        uint32_t v4 = seed - XXH_PRIME32_1;
        
        do {
            v1 += xxh_read32(p) * XXH_PRIME32_2; p += 4;
            v1 = xxh_rotl32(v1, 13);
            v1 *= XXH_PRIME32_1;
            
            v2 += xxh_read32(p) * XXH_PRIME32_2; p += 4;
            v2 = xxh_rotl32(v2, 13);
            v2 *= XXH_PRIME32_1;
            
            v3 += xxh_read32(p) * XXH_PRIME32_2; p += 4;
            v3 = xxh_rotl32(v3, 13);
            v3 *= XXH_PRIME32_1;
            
            v4 += xxh_read32(p) * XXH_PRIME32_2; p += 4;
            v4 = xxh_rotl32(v4, 13);
            v4 *= XXH_PRIME32_1;
        } while (p <= limit);
        
        h32 = xxh_rotl32(v1, 1) + xxh_rotl32(v2, 7) + 
              xxh_rotl32(v3, 12) + xxh_rotl32(v4, 18);
    }
    else
    {
        h32 = seed + XXH_PRIME32_5;
    }
    
    h32 += (uint32_t)len;
    
    while (p + 4 <= end)
    {
        h32 += xxh_read32(p) * XXH_PRIME32_3;
        h32 = xxh_rotl32(h32, 17) * XXH_PRIME32_4;
        p += 4;
    }
    
    while (p < end)
    {
        h32 += (*p++) * XXH_PRIME32_5;
        h32 = xxh_rotl32(h32, 11) * XXH_PRIME32_1;
    }
    
    h32 ^= h32 >> 15;
    h32 *= XXH_PRIME32_2;
    h32 ^= h32 >> 13;
    h32 *= XXH_PRIME32_3;
    h32 ^= h32 >> 16;
    
    return h32;
}

// Utility Functions
static inline uint64_t make_lookup_key(uint16_t caid, uint16_t srvid)
{
    return ((uint64_t)caid << 32) | srvid;
}

static int compare_keys(const void *a, const void *b)
{
    uint64_t ka = *(const uint64_t*)a;
    uint64_t kb = *(const uint64_t*)b;
    return (ka < kb) ? -1 : (ka > kb) ? 1 : 0;
}

static void secure_zero(void *ptr, size_t len)
{
    volatile uint8_t *p = ptr;
    while (len--) *p++ = 0;
}

// Filename Parser
static int parse_channel_filename(const char *filename, uint16_t *caid, 
                                   uint16_t *srvid, uint8_t *start, uint8_t *end)
{
    const char *bracket = strchr(filename, '[');
    const char *bracket_end = strchr(filename, ']');
    
    if (!bracket || !bracket_end || bracket_end <= bracket)
        return 0;
    
    char base[64];
    size_t len = bracket - filename;
    if (len >= sizeof(base)) return 0;
    
    memcpy(base, filename, len);
    base[len] = '\0';
    
    int s, e;
    if (sscanf(bracket, "[%d#%d]", &s, &e) != 2 || 
        s < 0 || s >= 256 || e <= s || e > 256)
        return 0;
    
    *start = (uint8_t)s;
    *end = (uint8_t)e;
    
    return sscanf(base, "%04hX@%04hX", caid, srvid) == 2;
}

// ECM Line Parser with Length Validation
static int parse_ecm_line(const char *line, uint8_t *ecm, uint8_t *cw, 
                          uint16_t *ecm_len, uint16_t expected_len)
{
    while (*line == ' ' || *line == '\t') line++;
    
    const char *cw_marker = strstr(line, " #CW ");
    if (!cw_marker) return 0;
    
    size_t hex_len = cw_marker - line;
    if (hex_len == 0 || hex_len % 2 != 0)
        return 0;
    
    *ecm_len = hex_len / 2;
    
    // Validate ECM length matches filename specification
    if (*ecm_len != expected_len)
        return 0;
    
    if (*ecm_len > ECMDB_MAX_ECM_LEN)
        return 0;
    
    for (size_t i = 0; i < *ecm_len; i++)
    {
        unsigned int byte;
        if (sscanf(line + i * 2, "%2x", &byte) != 1)
            return 0;
        ecm[i] = (uint8_t)byte;
    }
    
    const char *cw_start = cw_marker + 5;
    while (*cw_start == ' ' || *cw_start == '\t') cw_start++;
    
    if (cs_strlen(cw_start) < ECMDB_CW_LEN * 2)
        return 0;
    
    for (size_t i = 0; i < ECMDB_CW_LEN; i++)
    {
        unsigned int byte;
        if (sscanf(cw_start + i * 2, "%2x", &byte) != 1)
            return 0;
        cw[i] = (uint8_t)byte;
    }
    
    return 1;
}

// File Cache (DIRECT mode)
static ecmdb_cache_t* cache_find(uint32_t channel_idx)
{
    for (int i = 0; i < ECMDB_FILE_CACHE_SIZE; i++)
    {
        if (ecmdb->file_cache[i].fp && 
            ecmdb->file_cache[i].channel_idx == channel_idx)
        {
            ecmdb->file_cache[i].last_access = time(NULL);
            return &ecmdb->file_cache[i];
        }
    }
    return NULL;
}

static ecmdb_cache_t* cache_get_lru(void)
{
    ecmdb_cache_t *lru = NULL;
    time_t oldest = time(NULL);
    
    for (int i = 0; i < ECMDB_FILE_CACHE_SIZE; i++)
    {
        if (!ecmdb->file_cache[i].fp)
            return &ecmdb->file_cache[i];
            
        if (!ecmdb->file_cache[i].in_use && 
            ecmdb->file_cache[i].last_access < oldest)
        {
            oldest = ecmdb->file_cache[i].last_access;
            lru = &ecmdb->file_cache[i];
        }
    }
    return lru;
}

static FILE* cache_open(uint32_t channel_idx)
{
    ecmdb_cache_t *entry = cache_find(channel_idx);
    if (entry)
    {
        entry->in_use = 1;
        return entry->fp;
    }
    
    ecmdb_channel_t *ch = &ecmdb->channels[channel_idx];
    FILE *fp = fopen(ch->filepath, "r");
    if (!fp) return NULL;
    
    entry = cache_get_lru();
    if (!entry)
    {
        fclose(fp);
        return NULL;
    }
    
    if (entry->fp) fclose(entry->fp);
    
    entry->fp = fp;
    entry->channel_idx = channel_idx;
    entry->last_access = time(NULL);
    entry->in_use = 1;
    
    return fp;
}

static void cache_release(uint32_t channel_idx)
{
    for (int i = 0; i < ECMDB_FILE_CACHE_SIZE; i++)
    {
        if (ecmdb->file_cache[i].fp && 
            ecmdb->file_cache[i].channel_idx == channel_idx)
        {
            ecmdb->file_cache[i].in_use = 0;
            return;
        }
    }
}

static void cache_close_all(void)
{
    for (int i = 0; i < ECMDB_FILE_CACHE_SIZE; i++)
    {
        if (ecmdb->file_cache[i].fp)
        {
            fclose(ecmdb->file_cache[i].fp);
            ecmdb->file_cache[i].fp = NULL;
        }
    }
}

// RAM Mode - Channel Loading with Length Validation
static int load_channel_ram(ecmdb_channel_t *ch, const char *filepath,
                            uint8_t ecm_start, uint8_t ecm_end)
{
    FILE *fp = fopen(filepath, "r");
    if (!fp) return 0;
    
    uint16_t expected_len = ecm_end - ecm_start;
    
    ch->hash_table = calloc(ECMDB_HASH_SIZE, sizeof(ecmdb_entry_t*));
    if (!ch->hash_table)
    {
        fclose(fp);
        return 0;
    }
    
    size_t pool_size = 2 * 1024 * 1024;
    ch->data_pool = malloc(pool_size);
    if (!ch->data_pool)
    {
        free(ch->hash_table);
        fclose(fp);
        return 0;
    }
    
    ch->pool_size = pool_size;
    ch->pool_used = 0;
    
    char line[1024];
    uint8_t ecm_buf[ECMDB_MAX_ECM_LEN], cw_buf[ECMDB_CW_LEN];
    uint16_t ecm_len;
    
    uint32_t *seen = malloc(50000 * sizeof(uint32_t));
    uint32_t seen_count = 0;
    uint32_t skipped_count = 0;
    
    if (!seen)
    {
        free(ch->data_pool);
        free(ch->hash_table);
        fclose(fp);
        return 0;
    }
    
    while (fgets(line, sizeof(line), fp))
    {
        if (line[0] == '\n' || line[0] == '\r' || line[0] == '#')
            continue;
        
        // Parse with strict length validation
        if (!parse_ecm_line(line, ecm_buf, cw_buf, &ecm_len, expected_len))
        {
            skipped_count++;
            continue;
        }
        
        uint32_t hash = xxhash32(ecm_buf, ecm_len, 0);
        
        // Check duplicates
        int dup = 0;
        for (uint32_t i = 0; i < seen_count; i++)
        {
            if (seen[i] == hash)
            {
                dup = 1;
                break;
            }
        }
        if (dup) continue;
        
        // Expand pool if needed
        if (ch->pool_used + ecm_len > ch->pool_size)
        {
            size_t new_size = ch->pool_size * 2;
            if (new_size > 100 * 1024 * 1024) break;
            
            uint8_t *new_pool = realloc(ch->data_pool, new_size);
            if (!new_pool) break;
            
            ch->data_pool = new_pool;
            ch->pool_size = new_size;
        }
        
        // Add entry
        ecmdb_entry_t *entry = malloc(sizeof(ecmdb_entry_t));
        if (!entry) break;
        
        entry->ecm_data = ch->data_pool + ch->pool_used;
        memcpy(entry->ecm_data, ecm_buf, ecm_len);
        ch->pool_used += ecm_len;
        
        memcpy(entry->cw, cw_buf, ECMDB_CW_LEN);
        entry->ecm_len = ecm_len;
        entry->hash = hash;
        
        uint32_t idx = hash % ECMDB_HASH_SIZE;
        entry->next = ch->hash_table[idx];
        ch->hash_table[idx] = entry;
        
        if (seen_count < 50000)
            seen[seen_count++] = hash;
        
        ch->entry_count++;
    }
    
    secure_zero(ecm_buf, sizeof(ecm_buf));
    secure_zero(cw_buf, sizeof(cw_buf));
    free(seen);
    fclose(fp);
    
    if (skipped_count > 0)
    {
        cs_log("ECMDB: Skipped %u invalid entries (wrong length) in %s", 
               skipped_count, filepath);
    }
    
    return ch->entry_count > 0;
}

// ECM Search Functions
static int search_ecm_direct(FILE *fp, const uint8_t *ecm_data, size_t ecm_len,
                             uint8_t *cw, uint16_t expected_len)
{
    char line[1024];
    uint8_t line_ecm[ECMDB_MAX_ECM_LEN], line_cw[ECMDB_CW_LEN];
    uint16_t line_ecm_len;
    
    rewind(fp);
    
    while (fgets(line, sizeof(line), fp))
    {
        if (line[0] == '\n' || line[0] == '\r' || line[0] == '#')
            continue;
        
        if (!parse_ecm_line(line, line_ecm, line_cw, &line_ecm_len, expected_len))
            continue;
        
        if (line_ecm_len == ecm_len && 
            memcmp(ecm_data, line_ecm, ecm_len) == 0)
        {
            memcpy(cw, line_cw, ECMDB_CW_LEN);
            secure_zero(line_ecm, sizeof(line_ecm));
            secure_zero(line_cw, sizeof(line_cw));
            return 1;
        }
    }
    
    secure_zero(line_ecm, sizeof(line_ecm));
    secure_zero(line_cw, sizeof(line_cw));
    return 0;
}

static int search_ecm_ram(ecmdb_channel_t *ch, const uint8_t *ecm_data,
                          size_t ecm_len, uint8_t *cw)
{
    uint32_t hash = xxhash32(ecm_data, ecm_len, 0);
    uint32_t idx = hash % ECMDB_HASH_SIZE;
    
    ecmdb_entry_t *entry = ch->hash_table[idx];
    
    while (entry)
    {
        if (entry->hash == hash && 
            entry->ecm_len == ecm_len &&
            memcmp(ecm_data, entry->ecm_data, ecm_len) == 0)
        {
            memcpy(cw, entry->cw, ECMDB_CW_LEN);
            return 1;
        }
        entry = entry->next;
    }
    
    return 0;
}

// Channel Management
static int add_channel(const char *filepath, uint16_t caid, uint16_t srvid, 
                      uint8_t ecm_start, uint8_t ecm_end)
{
    if (ecmdb->channel_count >= ECMDB_MAX_CHANNELS) 
        return 0;
    
    ecmdb_channel_t *ch = &ecmdb->channels[ecmdb->channel_count];
    memset(ch, 0, sizeof(ecmdb_channel_t));
    
    ch->caid = caid;
    ch->srvid = srvid;
    ch->ecm_start = ecm_start;
    ch->ecm_end = ecm_end;
    ch->filepath = cs_strdup(filepath);
    
    if (!ch->filepath) return 0;
    
    if (ecmdb->mode == ECMDB_MODE_RAM)
    {
        if (!load_channel_ram(ch, filepath, ecm_start, ecm_end))
        {
            free(ch->filepath);
            return 0;
        }
        
        cs_log("ECMDB: %04X@%04X [%d#%d] %u entries (%zu KB)", 
               caid, srvid, ecm_start, ecm_end, 
               ch->entry_count, ch->pool_used / 1024);
    }
    else
    {
        cs_log("ECMDB: %04X@%04X [%d#%d] DIRECT mode", 
               caid, srvid, ecm_start, ecm_end);
    }
    
    ecmdb->lookup_keys[ecmdb->channel_count] = make_lookup_key(caid, srvid);
    ecmdb->channel_count++;
    
    return 1;
}

static void scan_directory(const char *path)
{
    DIR *dir = opendir(path);
    if (!dir) return;
    
    struct dirent *entry;
    char fullpath[512];
    
    while ((entry = readdir(dir)) && 
           ecmdb->channel_count < ECMDB_MAX_CHANNELS)
    {
        if (entry->d_name[0] == '.' || strstr(entry->d_name, ".."))
            continue;
        
        int ret = snprintf(fullpath, sizeof(fullpath), "%s/%s", 
                          path, entry->d_name);
        if (ret >= (int)sizeof(fullpath) || ret < 0) 
            continue;
        
        struct stat st;
        if (stat(fullpath, &st) != 0) continue;
        
        if (S_ISDIR(st.st_mode))
        {
            scan_directory(fullpath);
        }
        else if (S_ISREG(st.st_mode))
        {
            uint16_t caid, srvid;
            uint8_t start, end;
            
            if (parse_channel_filename(entry->d_name, &caid, &srvid, 
                                      &start, &end))
            {
                add_channel(fullpath, caid, srvid, start, end);
            }
        }
    }
    
    closedir(dir);
}

static ecmdb_channel_t* find_channel(uint16_t caid, uint16_t srvid, 
                                     uint32_t *out_idx)
{
    uint64_t key = make_lookup_key(caid, srvid);
    
    uint64_t *found = bsearch(&key, ecmdb->lookup_keys, 
                              ecmdb->channel_count,
                              sizeof(uint64_t), compare_keys);
    if (!found) return NULL;
    
    uint32_t idx = found - ecmdb->lookup_keys;
    if (out_idx) *out_idx = idx;
    
    return &ecmdb->channels[idx];
}

// Public API
int8_t ecmdb_init(struct s_reader *rdr)
{
    if (ecmdb) return EMU_OK;
    
    if (!rdr->ecmdb_path || cs_strlen(rdr->ecmdb_path) == 0)
        return EMU_NOT_SUPPORTED;
    
    struct stat st;
    if (stat(rdr->ecmdb_path, &st) != 0 || !S_ISDIR(st.st_mode))
    {
        cs_log("ECMDB: Invalid path: %s", rdr->ecmdb_path);
        return EMU_NOT_SUPPORTED;
    }
    
    ecmdb = calloc(1, sizeof(ecmdb_t));
    if (!ecmdb) return EMU_OUT_OF_MEMORY;
    
    ecmdb->channels = calloc(ECMDB_MAX_CHANNELS, sizeof(ecmdb_channel_t));
    ecmdb->lookup_keys = calloc(ECMDB_MAX_CHANNELS, sizeof(uint64_t));
    
    if (!ecmdb->channels || !ecmdb->lookup_keys)
    {
        free(ecmdb->channels);
        free(ecmdb->lookup_keys);
        free(ecmdb);
        ecmdb = NULL;
        return EMU_OUT_OF_MEMORY;
    }
    
    if (pthread_mutex_init(&ecmdb->lock, NULL) != 0)
    {
        free(ecmdb->channels);
        free(ecmdb->lookup_keys);
        free(ecmdb);
        ecmdb = NULL;
        return EMU_OUT_OF_MEMORY;
    }
    
    ecmdb->mode = (rdr->ecmdb_mode == 1) ? ECMDB_MODE_RAM : ECMDB_MODE_DIRECT;
    
    cs_log("ECMDB: Loading from %s [%s mode]", 
           rdr->ecmdb_path,
           ecmdb->mode == ECMDB_MODE_RAM ? "RAM" : "DIRECT");
    
    scan_directory(rdr->ecmdb_path);
    
    if (ecmdb->channel_count > 0)
    {
        qsort(ecmdb->lookup_keys, ecmdb->channel_count, 
              sizeof(uint64_t), compare_keys);
        
        size_t total_memory = 0;
        uint32_t total_entries = 0;
        
        for (uint32_t i = 0; i < ecmdb->channel_count; i++)
        {
            ecmdb_channel_t *ch = &ecmdb->channels[i];
            total_memory += ch->pool_used;
            total_entries += ch->entry_count;
        }
        
        cs_log("ECMDB: %u channels loaded, %u total entries", 
               ecmdb->channel_count, total_entries);
        
        if (ecmdb->mode == ECMDB_MODE_RAM)
        {
            cs_log("ECMDB: Memory: %.2f MB", total_memory / (1024.0f * 1024.0f));
        }
        
        ecmdb->initialized = 1;
    }
    else
    {
        cs_log("ECMDB: No channels found");
    }
    
    return EMU_OK;
}

int8_t ecmdb_ecm(uint16_t caid, uint16_t srvid, const uint8_t *ecm, uint8_t *cw)
{
    if (!ecmdb || !ecmdb->initialized)
        return EMU_NOT_SUPPORTED;
    
    SAFE_MUTEX_LOCK(&ecmdb->lock);
    
    uint32_t channel_idx;
    ecmdb_channel_t *ch = find_channel(caid, srvid, &channel_idx);
    
    if (!ch)
    {
        SAFE_MUTEX_UNLOCK(&ecmdb->lock);
        return EMU_KEY_NOT_FOUND;
    }
    
    size_t ecm_len = ch->ecm_end - ch->ecm_start;
    if (ecm_len == 0 || ch->ecm_start + ecm_len > ECMDB_MAX_ECM_LEN)
    {
        SAFE_MUTEX_UNLOCK(&ecmdb->lock);
        return EMU_CORRUPT_DATA;
    }
    
    const uint8_t *ecm_data = &ecm[ch->ecm_start];
    int found = 0;
    
    if (ecmdb->mode == ECMDB_MODE_RAM)
    {
        found = search_ecm_ram(ch, ecm_data, ecm_len, cw);
    }
    else
    {
        FILE *fp = cache_open(channel_idx);
        if (fp)
        {
            found = search_ecm_direct(fp, ecm_data, ecm_len, cw, ecm_len);
            cache_release(channel_idx);
        }
    }
    
    SAFE_MUTEX_UNLOCK(&ecmdb->lock);
    
    return found ? EMU_OK : EMU_CW_NOT_FOUND;
}

void ecmdb_cleanup(void)
{
    if (!ecmdb) return;
    
    SAFE_MUTEX_LOCK(&ecmdb->lock);
    
    cache_close_all();
    
    if (ecmdb->channels)
    {
        for (uint32_t i = 0; i < ecmdb->channel_count; i++)
        {
            ecmdb_channel_t *ch = &ecmdb->channels[i];
            
            if (ch->filepath) free(ch->filepath);
            
            if (ch->hash_table)
            {
                for (uint32_t j = 0; j < ECMDB_HASH_SIZE; j++)
                {
                    ecmdb_entry_t *entry = ch->hash_table[j];
                    while (entry)
                    {
                        ecmdb_entry_t *next = entry->next;
                        secure_zero(entry->cw, ECMDB_CW_LEN);
                        free(entry);
                        entry = next;
                    }
                }
                free(ch->hash_table);
            }
            
            if (ch->data_pool)
            {
                secure_zero(ch->data_pool, ch->pool_used);
                free(ch->data_pool);
            }
        }
        free(ecmdb->channels);
    }
    
    free(ecmdb->lookup_keys);
    
    SAFE_MUTEX_UNLOCK(&ecmdb->lock);
    pthread_mutex_destroy(&ecmdb->lock);
    
    free(ecmdb);
    ecmdb = NULL;
    
    cs_log("ECMDB: Cleanup complete");
}

#endif // WITH_EMU
