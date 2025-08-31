#define MODULE_LOG_PREFIX "ecmbin"
#include "globals.h"

#ifdef WITH_ECMBIN

#include "ncam-conf-chk.h"
#include "ncam-config.h"
#include "ncam-reader.h"
#include "ncam-string.h"
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <pthread.h>
#include <time.h>
#include <stdio.h>

#define CW_SIZE 16
#define FILENAME_SIZE 256
#define MAX_CHANNEL_FILES 1
#define MAX_CHANNELS 300
#define HASH_SIZE 64
#define CS_OK    1
#define CS_ERROR 0
#define CR_OK    0
#define CR_ERROR 1
#define PARTITION_SIZE 32

struct ECMEntry {
	uint8_t *ecm;
	uint8_t cw[CW_SIZE];
	uint32_t next_likely_index;  // For cache optimization
} __attribute__((packed));

struct BinFile {
	char filename[FILENAME_SIZE];
	struct ECMEntry *entries;
	size_t count;
	uint16_t caid;
	uint16_t srvid;
};

struct FileIndex {
	uint16_t caid;
	uint16_t srvid;
	size_t file_index;
};

struct FilePartition {
	struct BinFile files[PARTITION_SIZE];
	int file_count;
	pthread_rwlock_t lock;
};

static struct PreloadedData {
	struct FilePartition partitions[MAX_CHANNELS * MAX_CHANNEL_FILES / PARTITION_SIZE];
	struct FileIndex *indices;
	int total_files;
	int partition_count;
	time_t last_update;
} g_preloaded = {
	.total_files = 0,
	.partition_count = 0,
	.indices = NULL,
	.last_update = 0
};

static int compare_file_indices(const void *a, const void *b) {
	const struct FileIndex *fa = (const struct FileIndex *)a;
	const struct FileIndex *fb = (const struct FileIndex *)b;

	if (fa->caid != fb->caid)
		return fa->caid - fb->caid;
	return fa->srvid - fb->srvid;
}

static int compare_ecm(const void *a, const void *b) {
	size_t ecm_size = cfg.ecmbin_ecm_end_byte - cfg.ecmbin_ecm_start_byte;
	const struct ECMEntry *entry_a = (const struct ECMEntry *)a;
	const struct ECMEntry *entry_b = (const struct ECMEntry *)b;
	return memcmp(entry_a->ecm, entry_b->ecm, ecm_size);
}

static struct ECMEntry *load_and_sort_entries(const char *filename, size_t *count) {
	struct stat sb;
	size_t ecm_size = cfg.ecmbin_ecm_end_byte - cfg.ecmbin_ecm_start_byte;
	size_t entry_size = ecm_size + CW_SIZE;
	size_t i, j;
	int fd;
	struct ECMEntry *entries = NULL;
	uint8_t *temp_buffer = NULL;

	if ((fd = open(filename, O_RDONLY)) == -1) {
		cs_log("Error opening %s: %s", filename, strerror(errno));
		return NULL;
	}

	if (fstat(fd, &sb) == -1) {
		cs_log("Error getting size of %s: %s", filename, strerror(errno));
		close(fd);
		return NULL;
	}

	if (sb.st_size == 0 || sb.st_size % entry_size != 0) {
		cs_log("Invalid file size or format: %s", filename);
		close(fd);
		return NULL;
	}

	*count = sb.st_size / entry_size;
	if (!(entries = malloc(*count * sizeof(struct ECMEntry)))) {
		close(fd);
		return NULL;
	}

	if (!(temp_buffer = malloc(entry_size))) {
		free(entries);
		close(fd);
		return NULL;
	}

	for (i = 0; i < *count; i++) {
		if (read(fd, temp_buffer, entry_size) != (ssize_t)entry_size) {
			for (j = 0; j < i; j++)
				free(entries[j].ecm);
			free(entries);
			free(temp_buffer);
			close(fd);
			return NULL;
		}

		if (!(entries[i].ecm = malloc(ecm_size))) {
			for (j = 0; j < i; j++)
				free(entries[j].ecm);
			free(entries);
			free(temp_buffer);
			close(fd);
			return NULL;
		}

		memcpy(entries[i].ecm, temp_buffer, ecm_size);
		memcpy(entries[i].cw, temp_buffer + ecm_size, CW_SIZE);
	}

	free(temp_buffer);
	close(fd);

	qsort(entries, *count, sizeof(struct ECMEntry), compare_ecm);

	// Set next_likely_index for cache optimization
	for (i = 0; i < *count - 1; i++)
		entries[i].next_likely_index = i + 1;
	entries[*count - 1].next_likely_index = 0;

	return entries;
}

static size_t find_file_index(uint16_t caid, uint16_t srvid) {
	struct FileIndex key = {.caid = caid, .srvid = srvid};
	struct FileIndex *result = bsearch(&key, g_preloaded.indices, 
			g_preloaded.total_files, 
			sizeof(struct FileIndex), 
			compare_file_indices);
	return result ? result->file_index : (size_t)-1;
}

static int32_t search_ecm_in_sorted_entries(
	const struct ECMEntry *entries,
	size_t count,
	const uint8_t *ecm,
	struct s_ecm_answer *ea) {

	size_t ecm_size = cfg.ecmbin_ecm_end_byte - cfg.ecmbin_ecm_start_byte;
	size_t left = 0, right = count > 0 ? count - 1 : 0;

	while (left <= right) {
		size_t mid = left + (right - left) / 2;

		// Prefetch next likely entry
		if (count > 1 && mid < count - 1) {
			__builtin_prefetch(&entries[entries[mid].next_likely_index]);
		}

		int cmp = memcmp(ecm, entries[mid].ecm, ecm_size);
		if (cmp == 0) {
			memcpy(ea->cw, entries[mid].cw, CW_SIZE);
			return CS_OK;
		}
		if (cmp < 0) {
			if (mid == 0) break;
			right = mid - 1;
		} else {
			left = mid + 1;
		}
	}
	return CS_ERROR;
}

static int parse_filename(const char *filename, uint16_t *caid, uint16_t *srvid) {
	unsigned int ca, srv;
	if (sscanf(filename, "%04X@%04X", &ca, &srv) == 2) {
		*caid = (uint16_t)ca;
		*srvid = (uint16_t)srv;
		return 1;
	}
	return 0;
}

static void preload_all_bin_files(const char *directory)
{
	DIR *dir;
	struct dirent *entry;
	char fullpath[FILENAME_SIZE * 2];
	int i, current_file = 0, total_files = 0;
	struct ECMEntry *entries;
	size_t count;
	size_t dir_len;

	dir_len = strlen(directory);
	if (dir_len >= FILENAME_SIZE) {
		cs_log("Directory path too long: %s", directory);
		return;
	}

	// Initialize partitions
	for (i = 0; i < MAX_CHANNELS * MAX_CHANNEL_FILES / PARTITION_SIZE; i++) {
		pthread_rwlock_init(&g_preloaded.partitions[i].lock, NULL);
		g_preloaded.partitions[i].file_count = 0;
	}

	if (!(dir = opendir(directory))) {
		cs_log("Cannot open directory %s: %s", directory, strerror(errno));
		return;
	}

	// First pass: count files
	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_name[0] != '.') total_files++; // Count all non-hidden files
	}

	// Allocate indices array
	if (!(g_preloaded.indices = malloc(total_files * sizeof(struct FileIndex)))) {
		closedir(dir);
		return;
	}

	// Reset directory pointer
	rewinddir(dir);

	// Second pass: load files
	while ((entry = readdir(dir)) != NULL) {
		uint16_t caid, srvid;
		size_t name_len;

		if (entry->d_name[0] == '.') continue;

		name_len = strlen(entry->d_name);
		if (dir_len + name_len + 2 >= sizeof(fullpath)) {
			cs_log("Skipping long filename: %s/%s", directory, entry->d_name);
			continue;
		}

		if (!parse_filename(entry->d_name, &caid, &srvid)) {
			cs_log("Skipping invalid file: %s", entry->d_name);
			continue;
		}

		if (snprintf(fullpath, sizeof(fullpath), "%s/%s", directory, entry->d_name) < 0) {
			cs_log("Error creating path for: %s", entry->d_name);
			continue;
		}

		int partition_idx = current_file / PARTITION_SIZE;
		struct FilePartition *partition = &g_preloaded.partitions[partition_idx];

		pthread_rwlock_wrlock(&partition->lock);

		entries = load_and_sort_entries(fullpath, &count);
		if (entries && count > 0) {
			struct BinFile *file = &partition->files[partition->file_count];

			strncpy(file->filename, entry->d_name, FILENAME_SIZE);
			file->entries = entries;
			file->count = count;
			file->caid = caid;
			file->srvid = srvid;

			// Add to indices
			g_preloaded.indices[current_file].caid = caid;
			g_preloaded.indices[current_file].srvid = srvid;
			g_preloaded.indices[current_file].file_index = 
				partition_idx * PARTITION_SIZE + partition->file_count;

			partition->file_count++;
			current_file++;

			cs_log("Loaded %s (CAID: %04X, SRVID: %04X) with %zu entries",
				   entry->d_name, caid, srvid, count);
		}

		pthread_rwlock_unlock(&partition->lock);
	}

	closedir(dir);

	g_preloaded.total_files = current_file;
	g_preloaded.partition_count = (current_file + PARTITION_SIZE - 1) / PARTITION_SIZE;
	g_preloaded.last_update = time(NULL);

	// Sort indices for binary search
	qsort(g_preloaded.indices, g_preloaded.total_files, 
		  sizeof(struct FileIndex), compare_file_indices);

	cs_log("Successfully preloaded %d binary files in %d partitions", 
		   current_file, g_preloaded.partition_count);
}

static int32_t ecmbin_do_ecm(struct s_reader *UNUSED(rdr), const ECM_REQUEST *er, struct s_ecm_answer *ea) {
	size_t file_idx = find_file_index(er->caid, er->srvid);
	if (file_idx == (size_t)-1) {
		cs_log("No matching bin file for CAID: %04X, SRVID: %04X", er->caid, er->srvid);
		return CS_ERROR;
	}

	size_t partition_idx = file_idx / PARTITION_SIZE;
	size_t local_idx = file_idx % PARTITION_SIZE;
	struct FilePartition *partition = &g_preloaded.partitions[partition_idx];

	pthread_rwlock_rdlock(&partition->lock);

	const uint8_t *ecm = &er->ecm[cfg.ecmbin_ecm_start_byte];
	int32_t result = search_ecm_in_sorted_entries(
		partition->files[local_idx].entries,
		partition->files[local_idx].count,
		ecm,
		ea
	);

	pthread_rwlock_unlock(&partition->lock);

	return result;
}

static void cleanup(void) {
	int i, j;
	size_t k;
	// Clean up partitions
	for (i = 0; i < g_preloaded.partition_count; i++) {
		struct FilePartition *partition = &g_preloaded.partitions[i];
		pthread_rwlock_wrlock(&partition->lock);

		for (j = 0; j < partition->file_count; j++) {
			struct BinFile *file = &partition->files[j];
			if (file->entries) {
				for (k = 0; k < file->count; k++) {
					free(file->entries[k].ecm);
				}
				free(file->entries);
			}
		}

		partition->file_count = 0;
		pthread_rwlock_unlock(&partition->lock);
		pthread_rwlock_destroy(&partition->lock);
	}

	// Clean up indices
	free(g_preloaded.indices);
	g_preloaded.indices = NULL;

	g_preloaded.total_files = 0;
	g_preloaded.partition_count = 0;
	g_preloaded.last_update = 0;
}

static int32_t ecmbin_card_info(struct s_reader *rdr) {
	rdr->card_status = CARD_INSERTED;
	return CS_OK;
}

const struct s_cardsystem reader_ecmbin = {
	.desc = "ecmbin",
	.caids = (uint16_t[]){ 0x0B, 0 },
	.do_ecm = ecmbin_do_ecm,
	.card_info = ecmbin_card_info,
};

static int32_t ecmbin_reader_init(struct s_reader *UNUSED(reader)) {
	preload_all_bin_files(cfg.bin_folder);
	return CR_OK;
}

static int32_t ecmbin_close(struct s_reader *UNUSED(reader)) {
	cs_log("ECMBin reader shutting down");
	cleanup();
	return CR_OK;
}

static int32_t ecmbin_get_status(struct s_reader *UNUSED(reader), int32_t *in) { *in = 1; return CR_OK; }
static int32_t ecmbin_activate(struct s_reader *UNUSED(reader), struct s_ATR *UNUSED(atr)) { return CR_OK; }
static int32_t ecmbin_transmit(struct s_reader *UNUSED(reader), uint8_t *UNUSED(buffer),
	uint32_t UNUSED(size), uint32_t UNUSED(expectedlen), uint32_t UNUSED(delay),
	uint32_t UNUSED(timeout)) { return CR_OK; }
static int32_t ecmbin_receive(struct s_reader *UNUSED(reader), uint8_t *UNUSED(buffer),
	uint32_t UNUSED(size), uint32_t UNUSED(delay), uint32_t UNUSED(timeout)) { return CR_OK; }
static int32_t ecmbin_write_settings(struct s_reader *UNUSED(reader),
	struct s_cardreader_settings *UNUSED(s)) { return CR_OK; }
static int32_t ecmbin_card_write(struct s_reader *UNUSED(pcsc_reader),
	const uint8_t *UNUSED(buf), uint8_t *UNUSED(cta_res),
	uint16_t *UNUSED(cta_lr), int32_t UNUSED(l)) { return CR_OK; }
static int32_t ecmbin_set_protocol(struct s_reader *UNUSED(rdr),
	uint8_t *UNUSED(params), uint32_t *UNUSED(length),
	uint32_t UNUSED(len_request)) { return CR_OK; }

const struct s_cardreader cardreader_ecmbin = {
	.desc		= "ecmbin",
	.typ		= R_ECMBIN,
	.reader_init	= ecmbin_reader_init,
	.get_status	= ecmbin_get_status,
	.activate	= ecmbin_activate,
	.transmit	= ecmbin_transmit,
	.receive	= ecmbin_receive,
	.close		= ecmbin_close,
	.write_settings	= ecmbin_write_settings,
	.card_write	= ecmbin_card_write,
	.set_protocol	= ecmbin_set_protocol,
};

void add_ecmbin_reader(void) {
	LL_ITER itr;
	struct s_reader *rdr;
	int8_t haveBinReader = 0;
	char ecmbinName[] = "ecmemu";

	itr = ll_iter_create(configured_readers);
	while ((rdr = ll_iter_next(&itr))) {
		if (rdr->typ == R_ECMBIN) {
			haveBinReader = 1;
			break;
		}
	}

	if (!haveBinReader) {
		if (!cs_malloc(&rdr, sizeof(struct s_reader))) {
			return;
		}
		reader_set_defaults(rdr);
		rdr->enable = 1;
		rdr->typ = R_ECMBIN;
		cs_strncpy(rdr->label, ecmbinName, sizeof(ecmbinName));
		cs_strncpy(rdr->device, ecmbinName, sizeof(ecmbinName));
		rdr->grp = 0x2ULL;
		rdr->crdr = &cardreader_ecmbin;
		reader_fixups_fn(rdr);
		ll_append(configured_readers, rdr);
	}
}
#endif
