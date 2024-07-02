#include "globals.h"
#ifdef READER_DGCRYPT
#include "reader-common.h"

/********************************
*         Debug Reader          *
* Send = write to cardreader    *
* Recv = Answer from cardreader *
********************************/

struct dgcrypt_data
{
	uint8_t session_key[8];
};

static int32_t dgcrypt_cmd(struct s_reader *rdr, const uint8_t *cmd, const int32_t cmd_len, uint8_t *cta_res, uint16_t *cta_lr, const uint16_t min_len)
{
	rdr->ifsc = 195;
	rdr->ns = 1;

	if(reader_cmd2icc(rdr, cmd, cmd_len, cta_res, cta_lr)) // reader_cmd2icc retuns ERROR=1, OK=0 - the opposite of OK and ERROR defines in reader-common.h
	{
		rdr_log(rdr, "ERROR: reader_cmd2icc()");
		return ERROR;
	}

	if(*cta_lr < 2 || (min_len && (*cta_lr < min_len)))
	{
		if (cta_res[0] == 0x6b && cta_res[1] == 0x01) rdr_log(rdr, "ERROR: card has expired, please update your card");
		else rdr_log(rdr, "ERROR: response length (%d) is too short for %d", *cta_lr, min_len);
		return ERROR; // Response is too short
	}

	if(cta_res[*cta_lr - 2] != 0x90 || (cta_res[*cta_lr - 1] != 0x00 && cta_res[*cta_lr - 1] != 0x17))
	{
		rdr_log(rdr, "ERROR: %02X %02X", cta_res[*cta_lr - 2], cta_res[*cta_lr - 1]);
		return ERROR; // The reader responded with "command not OK"
	}
	return OK;
}
#define dgcrypt_cmd(cmd, cmd_len, min_len) { if(!dgcrypt_cmd(rdr, (const uint8_t*)cmd, cmd_len, cta_res, &cta_lr, min_len)) return ERROR; }

static int32_t dgcrypt_card_init(struct s_reader *rdr, ATR *newatr)
{
	def_resp
	get_atr

	if(atr_size < 8)
		{ return ERROR; }

	// Full ATR: 3B E9 00 00 81 31 C3 45 99 63 74 69 19 99 12 56 10 EC
	if(memcmp(atr, "\x3B\xE9\x00\x00\x81\x31\xC3\x45", 8) != 0)
		{ return ERROR; }

	if(!cs_malloc(&rdr->csystem_data, sizeof(struct dgcrypt_data)))
		{ return ERROR; }

	struct dgcrypt_data *csystem_data = rdr->csystem_data;

	rdr_log(rdr, "[dgcrypt-reader] card detected.");

	memset(rdr->sa, 0, sizeof(rdr->sa));
	memset(rdr->prid, 0, sizeof(rdr->prid));
	memset(rdr->hexserial, 0, sizeof(rdr->hexserial));
	memset(rdr->cardid, 0, sizeof(rdr->cardid));
	rdr->nprov = 1;

	// Get session key
	// Send: 81 D0 00 01 08
	// Recv: 32 86 17 D5 2C 66 61 14 90 00
	dgcrypt_cmd("\x81\xD0\x00\x01\x08", 5, 0x08)
	memcpy(csystem_data->session_key, cta_res, sizeof(csystem_data->session_key));

	// Get CAID
	// Send: 81 C0 00 01 0A // <-- 0A instead of 02 ...?
	// Recv: 4A BF 90 00
	dgcrypt_cmd("\x81\xC0\x00\x01\x0A", 5, 0x02) // ...
	rdr->caid = (cta_res[0] << 8) | cta_res[1];
	//rdr->caid = 0x4ABF;

	// Get serial number
	// Send: 81 D1 00 01 10
	// Recv: 00 0D DB 08 71 0D D5 0C 30 30 30 30 30 30 30 30 90 00
	dgcrypt_cmd("\x81\xD1\x00\x01\x10", 5, 0x08 /*0x10*/)
	memcpy(rdr->hexserial, cta_res + 1, 7);

	// Get card id
	// Send: 81 D4 00 01 05
	// Recv: 00 00 00 76 AC 90 00
	dgcrypt_cmd("\x81\xD4\x00\x01\x05", 5, 0x05)
	memcpy(rdr->cardid, cta_res, 5);

	// Get LABEL
	// Send: 81 D2 00 01 10
	// Recv: 50 61 79 5F 54 56 5F 43 61 72 64 00 00 00 00 00 90 00
	// Txt: P  a  y  _  T  V  _  C  a  r  d
	dgcrypt_cmd("\x81\xD2\x00\x01\x10", 5, 0x10)
	char label[17];
	memset(label, 0, sizeof(label));
	memcpy(label, cta_res, 16);

	// Get subsystem - !FIXME! We are not using the answer of this command!
	// Send: 81 DD 00 10 04
	// Recv: 00 55 00 55 90 00, also 00 8F 00 8F 90 00
	//dgcrypt_cmd("\x81\xDD\x00\x10\x04", 5, 0x04)

	rdr_log_sensitive(rdr, "CAID: 0x%04X, Serial: {%"PRIu64"} HexSerial: {%02X %02X %02X %02X %02X %02X %02X} Card Id: {%02X %02X %02X %02X %02X} Label: {%s}",
					rdr->caid,
					b2ll(7, rdr->hexserial),
					rdr->hexserial[0], rdr->hexserial[1], rdr->hexserial[2],
					rdr->hexserial[3], rdr->hexserial[4], rdr->hexserial[5], rdr->hexserial[6],
					rdr->cardid[0], rdr->cardid[1], rdr->cardid[2], rdr->cardid[3], rdr->cardid[4],
					label);

	return OK;
}

static int32_t dgcrypt_do_ecm(struct s_reader *rdr, const ECM_REQUEST *er, struct s_ecm_answer *ea)
{
	def_resp
	uint8_t cmd_buffer[256];
	struct dgcrypt_data *csystem_data = rdr->csystem_data;

	// The first 3 bytes of the ECM with the command
	memcpy(cmd_buffer, "\x80\xEA\x80", 3);
	memcpy(&cmd_buffer[3], &er->ecm[3], er->ecm[2] + 3);

	// Write ECM
	// Send: 80 EA 80 00 55 00 00 3F 90 03 00 00 18 5D 82 4E 01 C4 2D 60 12 ED 34 37 ED 72 .. .. ..
	// Recv: 72 25 8D A1 0D 0D D2 44 EE ED 51 2F 3B 5D 19 63 E6 90 00
	dgcrypt_cmd(cmd_buffer, er->ecm[2] + 3, 17)

	if(cta_res[0] != 0x72) // CW response MUST start with 0x72
		{ return ERROR; }

	int8_t i;
	for(i = 0; i < 16; i++)
	{
		ea->cw[i] = cta_res[1 + i] ^ csystem_data->session_key[i % 8];

		if((i + 1) % 4 == 0)
		{
			if(((ea->cw[i - 3] + ea->cw[i - 2] + ea->cw[i - 1]) & 0xFF) != ea->cw[i])
			{
				rdr_log(rdr, "ERROR: CW failed");
				return ERROR;
			}
		}
	}

	return OK;
}

static int32_t dgcrypt_do_emm(struct s_reader *rdr, EMM_PACKET *ep)
{
	def_resp
	uint8_t cmd_buffer[256];

	// The first 3 bytes of the EMM with the command
	memcpy(cmd_buffer, "\x80\xEB\x80", 3);
	memcpy(&cmd_buffer[3], &ep->emm[1], ep->emm[2] + 3);

	// Write EMM
	// Send: 80 EB 80 00 54 00 00 00 00 76 AC 00 8F 82 4A 90 03 00 00 .. .. ..
	// Recv: 90 17
	dgcrypt_cmd(cmd_buffer, ep->emm[2] + 3 + 2, 2)

	return OK;
}

static int32_t dgcrypt_get_emm_type(EMM_PACKET *ep, struct s_reader *rdr)
{
	rdr_log_dbg(rdr, D_EMM, "Entered dgcrypt_get_emm_type ep->emm[0]=%02x", ep->emm[0]);

	switch(ep->emm[0])
	{
		case 0x82:
			ep->type = UNIQUE;
			memset(ep->hexserial, 0, 8);
			memcpy(ep->hexserial, ep->emm + 4, 5);
#ifdef WITH_DEBUG
			if(cs_dblevel & D_EMM)
			{
				char tmp_dbg[5 * 2 + 1];
				rdr_log_dbg_sensitive(rdr, D_EMM, "UNIQUE, ep->hexserial = {%s}",
								cs_hexdump(1, ep->hexserial, 5, tmp_dbg, sizeof(tmp_dbg)));

				rdr_log_dbg_sensitive(rdr, D_EMM, "UNIQUE, rdr->cardid = {%s}",
								cs_hexdump(1, rdr->cardid, 5, tmp_dbg, sizeof(tmp_dbg)));
			}
#endif
			return (!memcmp(rdr->cardid, ep->hexserial, 5));
			// Unknown EMM types, but allready subbmited to dev's
			// FIXME: Drop EMM's until there are implemented
		default:
			ep->type = UNKNOWN;
			rdr_log_dbg(rdr, D_EMM, "UNKNOWN");
			return 1;
	}
}

static int32_t dgcrypt_get_emm_filter(struct s_reader *rdr, struct s_csystem_emm_filter **emm_filters, unsigned int *filter_count)
{
	if(*emm_filters == NULL)
	{
		// need more info
		//--|-|len|--|card id 5 byte|  const |len|const|--------------
		//82 00 54 00 00 00 00 xx xx 00 8f 82 4a 90 03 ...  tested, works
		//82 00 64 00 00 00 00 00 00 00 8f 82 5a ff ff ...  ? filler
		//82 00 34 00 00 00 00 xx xx 00 8f 82 2a 90 03 ...  ?
		//82 00 37 00 00 00 00 xx xx 00 8f 82 2d 90 03 ...  ?

		const unsigned int max_filter_count = 1; // fixme
		if(!cs_malloc(emm_filters, max_filter_count * sizeof(struct s_csystem_emm_filter)))
		{
			return ERROR;
		}

		struct s_csystem_emm_filter *filters = *emm_filters;

		int32_t idx = 0;

		filters[idx].type = EMM_UNIQUE;
		filters[idx].enabled = 1;
		filters[idx].filter[0] = 0x82;
		filters[idx].mask[0] = 0xFF;
		memcpy(&filters[idx].filter[2], rdr->cardid, 5);
		memset(&filters[idx].mask[2], 0xFF, 5);
		idx++;
/*
		// I've never seen it
		filters[idx].type = EMM_GLOBAL;
		filters[idx].enabled = 1;
		filters[idx].filter[0] = 0x83;
		filters[idx].mask[0] = 0xFF;
		idx++;
*/
		*filter_count = idx;
	}

	return OK;
}

const struct s_cardsystem reader_dgcrypt =
{
	.desc           = "dgcrypt",
	.caids          = (uint16_t[]){ 0x4AB0, 0x4ABF, 0 },
	.card_init      = dgcrypt_card_init,
	.do_emm         = dgcrypt_do_emm,
	.do_ecm         = dgcrypt_do_ecm,
	.get_emm_type   = dgcrypt_get_emm_type,
	.get_emm_filter = dgcrypt_get_emm_filter,
};

#endif
