#ifndef READER_COMMON_H_
#define READER_COMMON_H_

//Warning: OK = 0 and ERROR = 1 in csctapi !!!
#define SKIPPED 2
#define OK      1
#define ERROR   0

#include "csctapi/atr.h"
#include "ncam-string.h"
#include "ncam-reader.h"

int32_t reader_cmd2icc(struct s_reader *reader, const uint8_t *buf, const int32_t l, uint8_t *response, uint16_t *response_length);
int32_t card_write(struct s_reader *reader, const uint8_t *, const uint8_t *, uint8_t *, uint16_t *);

#define write_cmd(cmd, data) \
	{ \
		if (card_write(reader, cmd, data, cta_res, &cta_lr)) return ERROR; \
	}

#define get_atr \
	uint8_t atr[ATR_MAX_SIZE]; \
	uint32_t atr_size; \
	memset(atr, 0, sizeof(atr)); \
	ATR_GetRaw(newatr, atr, &atr_size);

#define get_atr2 \
	uint8_t atr2[ATR_MAX_SIZE]; \
	uint32_t atr_size2; \
	memset(atr2, 0, sizeof(atr2)); \
	ATR_GetRaw(newatr, atr2, &atr_size2);

#define get_hist \
	uint8_t hist[ATR_MAX_HISTORICAL]; \
	uint32_t hist_size = 0; \
	ATR_GetHistoricalBytes(newatr, hist, &hist_size);

#define def_resp \
	uint8_t cta_res[CTA_RES_LEN]; \
	memset(cta_res, 0, CTA_RES_LEN); \
	uint16_t cta_lr;

#ifdef WITH_CARDREADER
void cardreader_init_locks(void);
bool cardreader_init(struct s_reader *reader);
void cardreader_close(struct s_reader *reader);
void cardreader_do_reset(struct s_reader *reader);
void cardreader_reset(struct s_client *cl);
int32_t cardreader_do_checkhealth(struct s_reader *reader);
void cardreader_checkhealth(struct s_client *cl, struct s_reader *rdr);
int32_t cardreader_do_emm(struct s_reader *reader, EMM_PACKET *ep);
#if defined(WITH_SENDCMD) && defined(READER_VIDEOGUARD)
int32_t cardreader_do_rawcmd(struct s_reader *reader, CMD_PACKET *cp);
#endif
void cardreader_process_ecm(struct s_reader *reader, struct s_client *cl, ECM_REQUEST *er);
void cardreader_get_card_info(struct s_reader *reader);
void cardreader_poll_status(struct s_reader *reader);
int32_t check_sct_len(const uint8_t *data, int32_t off, int32_t maxSize);
#else
static inline void cardreader_init_locks(void) { }
static inline bool cardreader_init(struct s_reader *UNUSED(reader))
{
	return true;
}
static inline void cardreader_close(struct s_reader *UNUSED(reader)) { }
static inline void cardreader_do_reset(struct s_reader *UNUSED(reader))
{
	return;
}
static inline void cardreader_reset(struct s_client *UNUSED(cl)) { }
static inline int32_t cardreader_do_checkhealth(struct s_reader *UNUSED(reader))
{
	return false;
}
static inline void cardreader_checkhealth(struct s_client *UNUSED(cl), struct s_reader *UNUSED(rdr)) { }
static inline int32_t cardreader_do_emm(struct s_reader *UNUSED(reader), EMM_PACKET *UNUSED(ep))
{
	return 0;
}
static inline void cardreader_process_ecm(struct s_reader *UNUSED(reader), struct s_client *UNUSED(cl), ECM_REQUEST *UNUSED(er)) { }
static inline void cardreader_get_card_info(struct s_reader *UNUSED(reader)) { }
static inline void cardreader_poll_status(struct s_reader *UNUSED(reader)) { }
#endif

#endif
