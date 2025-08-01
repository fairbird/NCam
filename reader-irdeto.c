#include "globals.h"
#ifdef READER_IRDETO
#include "ncam-time.h"
#include "reader-common.h"
#include "reader-irdeto.h"

static const uint8_t CryptTable[256] =
{
	0xDA, 0x26, 0xE8, 0x72, 0x11, 0x52, 0x3E, 0x46,
	0x32, 0xFF, 0x8C, 0x1E, 0xA7, 0xBE, 0x2C, 0x29,
	0x5F, 0x86, 0x7E, 0x75, 0x0A, 0x08, 0xA5, 0x21,
	0x61, 0xFB, 0x7A, 0x58, 0x60, 0xF7, 0x81, 0x4F,
	0xE4, 0xFC, 0xDF, 0xB1, 0xBB, 0x6A, 0x02, 0xB3,
	0x0B, 0x6E, 0x5D, 0x5C, 0xD5, 0xCF, 0xCA, 0x2A,
	0x14, 0xB7, 0x90, 0xF3, 0xD9, 0x37, 0x3A, 0x59,
	0x44, 0x69, 0xC9, 0x78, 0x30, 0x16, 0x39, 0x9A,
	0x0D, 0x05, 0x1F, 0x8B, 0x5E, 0xEE, 0x1B, 0xC4,
	0x76, 0x43, 0xBD, 0xEB, 0x42, 0xEF, 0xF9, 0xD0,
	0x4D, 0xE3, 0xF4, 0x57, 0x56, 0xA3, 0x0F, 0xA6,
	0x50, 0xFD, 0xDE, 0xD2, 0x80, 0x4C, 0xD3, 0xCB,
	0xF8, 0x49, 0x8F, 0x22, 0x71, 0x84, 0x33, 0xE0,
	0x47, 0xC2, 0x93, 0xBC, 0x7C, 0x3B, 0x9C, 0x7D,
	0xEC, 0xC3, 0xF1, 0x89, 0xCE, 0x98, 0xA2, 0xE1,
	0xC1, 0xF2, 0x27, 0x12, 0x01, 0xEA, 0xE5, 0x9B,
	0x25, 0x87, 0x96, 0x7B, 0x34, 0x45, 0xAD, 0xD1,
	0xB5, 0xDB, 0x83, 0x55, 0xB0, 0x9E, 0x19, 0xD7,
	0x17, 0xC6, 0x35, 0xD8, 0xF0, 0xAE, 0xD4, 0x2B,
	0x1D, 0xA0, 0x99, 0x8A, 0x15, 0x00, 0xAF, 0x2D,
	0x09, 0xA8, 0xF5, 0x6C, 0xA1, 0x63, 0x67, 0x51,
	0x3C, 0xB2, 0xC0, 0xED, 0x94, 0x03, 0x6F, 0xBA,
	0x3F, 0x4E, 0x62, 0x92, 0x85, 0xDD, 0xAB, 0xFE,
	0x10, 0x2E, 0x68, 0x65, 0xE7, 0x04, 0xF6, 0x0C,
	0x20, 0x1C, 0xA9, 0x53, 0x40, 0x77, 0x2F, 0xA4,
	0xFA, 0x6D, 0x73, 0x28, 0xE2, 0xCD, 0x79, 0xC8,
	0x97, 0x66, 0x8E, 0x82, 0x74, 0x06, 0xC7, 0x88,
	0x1A, 0x4A, 0x6B, 0xCC, 0x41, 0xE9, 0x9D, 0xB8,
	0x23, 0x9F, 0x3D, 0xBF, 0x8D, 0x95, 0xC5, 0x13,
	0xB9, 0x24, 0x5A, 0xDC, 0x64, 0x18, 0x38, 0x91,
	0x7F, 0x5B, 0x70, 0x54, 0x07, 0xB6, 0x4B, 0x0E,
	0x36, 0xAC, 0x31, 0xE6, 0xD6, 0x48, 0xAA, 0xB4
};

static const uint8_t sc_T14GetCountryCode[] = { 0x02, 0x02, 0x03, 0x00, 0x00 };
static const uint8_t sc_T14GetCountryCode2[] = { 0x02, 0x0B, 0x00, 0x00, 0x00 };

static const uint8_t sc_T14GetCamKey384DZ[] =
{
	0x02, 0x09, 0x03, 0x00, 0x40,
	0x27, 0xF2, 0xD6, 0xCD, 0xE6, 0x88, 0x62, 0x46,
	0x81, 0xB0, 0xF5, 0x3E, 0x6F, 0x13, 0x4D, 0xCC,
	0xFE, 0xD0, 0x67, 0xB1, 0x93, 0xDD, 0xF4, 0xDE,
	0xEF, 0xF5, 0x3B, 0x04, 0x1D, 0xE5, 0xC3, 0xB2,
	0x54, 0x38, 0x57, 0x7E, 0xC8, 0x39, 0x07, 0x2E,
	0xD2, 0xF4, 0x05, 0xAA, 0x15, 0xB5, 0x55, 0x24,
	0x90, 0xBB, 0x9B, 0x00, 0x96, 0xF0, 0xCB, 0xF1,
	0x8A, 0x08, 0x7F, 0x0B, 0xB8, 0x79, 0xC3, 0x5D
};

/* some variables for T0 protocol card */
#define T0EMM 0xD1
#define T0ECM 0xD5
#define T0GET 0xD2
/* end define */

typedef struct chid_base_date
{
	uint16_t caid;
	uint16_t acs;
	char c_code[4];
	uint32_t base;
} CHID_BASE_DATE;

struct irdeto_data
{
	int32_t t0; // A flag for T0 protocol card
	uint16_t acs;
	char country_code[3]; // irdeto country code.
};

static void XRotateLeft8Byte(uint8_t *buf)
{
	int32_t k;
	uint8_t t1 = buf[7];
	uint8_t t2 = 0;

	for(k = 0; k <= 7; k++)
	{
		t2 = t1;
		t1 = buf[k];
		buf[k] = (buf[k] << 1) | (t2 >> 7);
	}
}

static void ReverseSessionKeyCrypt(const uint8_t *camkey, uint8_t *key)
{
	uint8_t localkey[8], tmp1, tmp2;
	int32_t idx1, idx2;

	memcpy(localkey, camkey, 8);

	for(idx1 = 0; idx1 < 8; idx1++)
	{
		for(idx2 = 0; idx2 < 8; idx2++)
		{
			tmp1 = CryptTable[key[7] ^ localkey[idx2] ^ idx1];
			tmp2 = key[0];
			key[0] = key[1];
			key[1] = key[2];
			key[2] = key[3];
			key[3] = key[4];
			key[4] = key[5];
			key[5] = key[6] ^ tmp1;
			key[6] = key[7];
			key[7] = tmp1 ^ tmp2;
		}
		XRotateLeft8Byte(localkey);
	}
}

static time_t chid_date(struct s_reader *reader, uint32_t date, char *buf, int32_t l)
{
	// Irdeto date starts 01.08.1997 which is
	// 870393600 seconds in unix calendar time
	//
	// The above might not be true for all Irdeto card
	// we need to find a way to identify cards to set the base date
	// like we did for NDS
	//
	// this is the known default value.

	uint32_t date_base;

	if((reader->caid >> 8) == 0x06)
	{
		date_base = 946598400L; // this is actually 31.12.1999, 00:00 default for irdeto card
	}
	else
	{
		date_base = 870393600L; // this is actually 01.08.1997, 00:00 default for betacrypt cards
	}

		// CAID,  ACS,  Country, base date			D. M.   Y, h : m
	CHID_BASE_DATE table[] = {
		{0x0616, 0x0608, "ITA", 944110500L},	// 01.12.1999, 23.55	//nitegate
		{0x0647, 0x0005, "ITA", 946598400L},	// 31.12.1999, 00:00	//Redlight irdeto
		{0x0664, 0x0608, "TUR", 946598400L},	// 31.12.1999, 00:00
		{0x0624, 0x0006, "CZE", 946598400L},	// 30.12.1999, 16:00	//skyklink irdeto
		{0x0624, 0x0006, "SVK", 946598400L},	// 30.12.1999, 16:00	//skyklink irdeto
		{0x0666, 0x0006, "SVK", 946598400L},	// 30.12.1999, 16:00	//cslink irdeto
		{0x0668, 0x0006, "SVK", 946598400L},	// 30.12.1999, 00:00	//Towercom Irdeto
		{0x0666, 0x0006, "CZE", 946598400L},	// 30.12.1999, 16:00	//cslink irdeto
		{0x0653, 0x0608, "HUN", 946598400L},	// 31.12.1999, 00:00	//upc ice irdeto
		{0x0653, 0x0005, "HUN", 946598400L},	// 31.12.1999, 00:00	//upc ice irdeto
		{0x0650, 0x0608, "AUT", 946598400L},	// 31.12.1999, 00:00	//orf P410 irdeto
		{0x0650, 0x0005, "AUT", 946598400L},	// 31.12.1999, 00:00	//orf P410 irdeto
		{0x0648, 0x0608, "AUT", 946598400L},	// 31.12.1999, 00:00	//orf ice irdeto
		{0x0648, 0x0005, "AUT", 946598400L},	// 31.12.1999, 00:00	//orf ice irdeto
		{0x0627, 0x0608, "EGY", 946598400L},	// 30.12.1999, 16:00
		{0x0602, 0x0606, "NLD", 946598400L},	// 31.12.1999, 08:00	//Ziggo irdeto caid: 0602, acs: 6.06
		{0x0602, 0x0505, "NLD", 946598400L},	// 31.12.1999, 00:00	//Ziggo irdeto caid: 0602, acs: 5.05
		{0x0606, 0x0005, "NLD", 946598400L},	// 31.12.1999, 00:00	//Caiway irdeto card caid: 0606, acs: 0.05
		{0x0606, 0x0605, "NLD", 946598400L},	// 31.12.1999, 00:00	//Caiway irdeto card caid: 0606, acs: 6.05
		{0x0606, 0x0606, "NLD", 946598400L},	// 31.12.1999, 00:00	//Caiway irdeto card caid: 0606, acs: 6.06
		{0x0606, 0x0006, "ZAF", 946598400L},	// 31.12.1999, 00:00	//dstv irdeto
		{0x0604, 0x1541, "GRC", 977817600L},	// 26.12.2000, 00:00
		{0x0604, 0x1542, "GRC", 977817600L},	// 26.12.2000, 00:00
		{0x0604, 0x1543, "GRC", 977817600L},	// 26.12.2000, 00:00
		{0x0604, 0x1544, "GRC", 977817600L},	// 26.12.2000, 17:00
		{0x0604, 0x0608, "EGY", 999993600L},	// 08.09.2001, 17:00
		{0x0604, 0x0606, "EGY", 1003276800L},	// 16.10.2001, 17:00
		{0x0604, 0x0605, "GRC", 1011052800L},	// 15.01.2002, 00:00	//nova irdeto
		{0x0604, 0x0606, "GRC", 1011052800L},	// 15.01.2002, 00:00	//nova irdeto
		{0x0604, 0x0607, "GRC", 1011052800L},	// 15.01.2002, 00:00	//nova irdeto
		{0x0604, 0x0608, "GRC", 1011052800L},	// 15.01.2002, 00:00	//nova irdeto
		{0x0604, 0x0005, "GRC", 1011052800L},	// 15.01.2002, 00:00	//mova irdeto
		{0x0604, 0x0606, "NLD", 1066089600L},	// 14.10.2003, 00:00
		{0x0610, 0x0608, "NLD", 1066089600L},	// 14.10.2003, 00:00	//Ziggo irdeto caid: 0610, acs: 6.08
		{0x0604, 0x0608, "NLD", 1066089600L},	// 14.10.2003, 00:00	//Ziggo irdeto caid: 0604, acs: 6.08
		{0x0604, 0x0605, "NLD", 1066089600L},	// 14.10.2003, 00:00	//Ziggo irdeto caid: 0604, acs: 6.05
		{0x0604, 0x0005, "NLD", 1066089600L},	// 14.10.2003, 00:00	//Ziggo irdeto caid: 0604, acs: 0.05
		{0x0628, 0x0606, "MCR", 1159574400L},	// 29.09.2006, 00:00
		{0x0652, 0x0005, "MCR", 1206662400L},	// 28.03.2008, 00:00	//Raduga caid:0652, acs: 0.05
		{0x0652, 0x0608, "MCR", 1206662400L},	// 28.03.2008, 00:00	//Raduga caid:0652, acs: 6.08
		{0x0, 0x0, "", 0L}
	};

	// now check for specific providers base date
	int32_t i = 0;
	struct irdeto_data *csystem_data = reader->csystem_data;

	while(table[i].caid)
	{
		if((reader->caid == table[i].caid) && (csystem_data->acs == table[i].acs)
			&& (!memcmp(csystem_data->country_code, table[i].c_code, 3)))
		{
			date_base = table[i].base;
			break;
		}
		i++;
	}

	time_t ut = date_base + date * (24 * 3600);
	if(buf)
	{
		struct tm t;
		cs_gmtime_r(&ut, &t);
		l = 27;
		snprintf(buf, l, "%04d/%02d/%02d", t.tm_year + 1900, t.tm_mon + 1, t.tm_mday);
	}
	return (ut);
}

static int32_t irdeto_do_cmd(struct s_reader *reader, uint8_t *buf, uint16_t good, uint8_t *cta_res, uint16_t *p_cta_lr)
{
	int32_t rc;
	if((rc = reader_cmd2icc(reader, buf, buf[4] + 5, cta_res, p_cta_lr)))
	{
		return (rc); // result may be 0 (success) or negative
	}

	if(*p_cta_lr < 2)
	{
		return (0x7F7F); // this should never happen
	}

	return (good != b2i(2, cta_res + *p_cta_lr - 2));
}

#define reader_chk_cmd(cmd, l) { if (reader_cmd2icc(reader, cmd, sizeof(cmd), cta_res, &cta_lr)) return ERROR; if (l && (cta_lr!=l)) return ERROR; }

static int32_t irdeto_card_init_provider(struct s_reader *reader)
{
	def_resp;
	int32_t i, p;
	uint8_t buf[256] = {0};
	struct irdeto_data *csystem_data = reader->csystem_data;

	uint8_t sc_T14GetProvider[] = { 0x02, 0x03, 0x03, 0x00, 0x00 };
	uint8_t sc_T0Prov[] = { 0xD2, 0x06, 0x03, 0x00, 0x01, 0x3C };
	uint8_t sc_T0_Cmd[] = { T0GET, 0xFE, 0x00, 0x00, 0x00 };

	/*
	 * Provider
	 */
	memset(reader->prid, 0xff, sizeof(reader->prid));

	for(buf[0] = i = p = 0; i < reader->nprov; i++)
	{
		int32_t anspadd = 0;
		if(csystem_data->t0 == 1)
		{
			anspadd = 8;
			sc_T0Prov[3] = i;
			irdeto_do_cmd(reader, sc_T0Prov, 0x9021, cta_res, &cta_lr);
			int32_t anslength = cta_res[cta_lr - 1];
			sc_T0_Cmd[4] = anslength;
			reader_chk_cmd(sc_T0_Cmd, anslength + 2);
			sc_T0Prov[5]++;
			sc_T0_Cmd[3]++;
		}
		else
		{
			sc_T14GetProvider[3] = i;
			reader_chk_cmd(sc_T14GetProvider, 0);
		}

		if(((cta_lr == 26) && ((!(i & 1)) || (cta_res[0] != 0xf))) || (csystem_data->t0 == 1))
		{
			reader->prid[i][4] = p++;

			// maps the provider id for Betacrypt from FFFFFF to 000000,
			// fixes problems with cascading CCcam and NCam
			if(caid_is_betacrypt(reader->caid))
			{
				memset(&reader->prid[i][0], 0, 4);
			}
			else
			{
				memcpy(&reader->prid[i][0], cta_res + anspadd, 4);
			}

			if(!memcmp(cta_res + anspadd + 1, &reader->hexserial, 3))
			{
				reader->prid[i][3] = 0xFF;
			}

			snprintf((char *) buf + cs_strlen((char *)buf), sizeof(buf) - cs_strlen((char *)buf), ",%06x", b2i(3, &reader->prid[i][1]));
		}
		else
		{
			reader->prid[i][0] = 0xf;
		}
	}

	if(p)
	{
		rdr_log_sensitive(reader, "active providers: %d {(%s)}", p, buf + 1);
	}

	return OK;
}

static int32_t irdeto_card_init(struct s_reader *reader, ATR *newatr)
{
	def_resp;
	get_atr;
	uint8_t buf[256] = { 0 };
	uint8_t sc_T14GetCamKey383C[] = {
		0x02, 0x09, 0x03, 0x00, 0x40,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

	uint8_t sc_T14GetASCIISerial[] = { 0x02, 0x00, 0x03, 0x00, 0x00 };
	uint8_t sc_T14GetHEXSerial[] = { 0x02, 0x01, 0x00, 0x00, 0x00 };
	uint8_t sc_T14GetSCDetails[] = { 0x02, 0x1E, 0x00, 0x00, 0x00 };
	uint8_t sc_T14GetCardFile[] = { 0x02, 0x0E, 0x02, 0x00, 0x00 };

	uint8_t sc_T0CamKey[70] = { 0xD2, 0x12, 0x00, 0x00, 0x41};
	uint8_t sc_T0Country[] = { 0xD2, 0x04, 0x00, 0x00, 0x01, 0x3E };
	uint8_t sc_T0Ascii[] = { 0xD2, 0x00, 0x03, 0x00, 0x01, 0x3F };
	uint8_t sc_T0Hex[] = { 0xD2, 0x02, 0x03, 0x00, 0x01, 0x3E };
	uint8_t sc_T0SCDetails[] = { 0xD2, 0x3C, 0x00, 0x00, 0x01, 0x22 };
	uint8_t sc_T0CFile[] = { 0xD2, 0x1C, 0x02, 0x00, 0x01, 0x30 };
	uint8_t sc_T0_Cmd[] = { T0GET, 0xFE, 0x00, 0x00, 0x00 };

	int32_t anspadd = 0;
	int32_t t0 = 0;

	if(!memcmp(atr + 4, "IRDETO", 6))
	{
		t0 = 0;
	}
	else
	{
		if((!memcmp(atr + 5, "IRDETO", 6)) || (((atr[6] == 0xC4) && (atr[9] == 0x8F) && (atr[10] == 0xF1)) && reader->force_irdeto))
		{
			t0 = 1;
			anspadd = 8;
			rdr_log(reader, "Hist. Bytes: %s", atr + 5);
		}
		else
		{
			return ERROR;
		}
	}

	if(!cs_malloc(&reader->csystem_data, sizeof(struct irdeto_data)))
	{
		return ERROR;
	}
	struct irdeto_data *csystem_data = reader->csystem_data;
	csystem_data->t0 = t0;

	rdr_log(reader, "detect irdeto card");
	if((array_has_nonzero_byte(reader->rsa_mod, 64) > 0) && (!reader->force_irdeto || csystem_data->t0)) // we use rsa from config as camkey
	{
		char tmp_dbg[65];
		rdr_log_dbg(reader, D_READER, "using camkey data from config");
		rdr_log_dbg(reader, D_READER, "     camkey: %s", cs_hexdump(0, reader->boxkey, sizeof(reader->boxkey), tmp_dbg, sizeof(tmp_dbg)));
		if(csystem_data->t0 == 1)
		{
			memcpy(&sc_T0CamKey[5], reader->rsa_mod, 0x40);
			rdr_log_dbg(reader, D_READER, "camkey-data: %s", cs_hexdump(0, &sc_T0CamKey[5], 32, tmp_dbg, sizeof(tmp_dbg)));
			rdr_log_dbg(reader, D_READER, "camkey-data: %s", cs_hexdump(0, &sc_T0CamKey[37], 32, tmp_dbg, sizeof(tmp_dbg)));
		}
		else
		{
			memcpy(&sc_T14GetCamKey383C[5], reader->rsa_mod, 0x40);
			rdr_log_dbg(reader, D_READER, "camkey-data: %s", cs_hexdump(0, &sc_T14GetCamKey383C[5], 32, tmp_dbg, sizeof(tmp_dbg)));
			rdr_log_dbg(reader, D_READER, "camkey-data: %s", cs_hexdump(0, &sc_T14GetCamKey383C[37], 32, tmp_dbg, sizeof(tmp_dbg)));
		}
	}
	else
	{
		if(csystem_data->t0 == 1)
		{
			rdr_log(reader, "WARNING: T0 protocol card can require the CamKey from config");
		}
		else
		{
			memcpy(reader->boxkey, "\x11\x22\x33\x44\x55\x66\x77\x88", 8);
		}
	}

	/*
	 * Get Irdeto Smartcard Details - version - patch level etc
	 */
	if(csystem_data->t0 == 1)
	{
		irdeto_do_cmd(reader, sc_T0SCDetails, 0x9015, cta_res, &cta_lr);
		int32_t anslength = cta_res[cta_lr - 1];
		sc_T0_Cmd[4] = anslength;
		reader_chk_cmd(sc_T0_Cmd, anslength + 2);
		rdr_log(reader, "Irdeto SC %0x version %0x revision %0x, patch level %0x", cta_res[0 + anspadd], cta_res[1 + anspadd], cta_res[2 + anspadd], cta_res[5 + anspadd]);
	}
	else
	{
		if(!irdeto_do_cmd(reader, sc_T14GetSCDetails, 0, cta_res, &cta_lr))
		{
			rdr_log(reader, "Irdeto SC %0x version %0x revision %0x, patch level %0x", cta_res[0 + anspadd], cta_res[1 + anspadd], cta_res[2 + anspadd], cta_res[5 + anspadd]);
		}
	}

	/*
	 * CountryCode
	 */
	if(csystem_data->t0 == 1)
	{
		irdeto_do_cmd(reader, sc_T0Country, 0x9019, cta_res, &cta_lr);
		int32_t anslength = cta_res[cta_lr - 1];
		sc_T0_Cmd[4] = anslength;
		reader_chk_cmd(sc_T0_Cmd, anslength + 2);
	}
	else
	{
		reader_chk_cmd(sc_T14GetCountryCode, 18);
	}
	csystem_data->acs = (cta_res[0 + anspadd] << 8) | cta_res[1 + anspadd];
	reader->caid = (cta_res[5 + anspadd] << 8) | cta_res[6 + anspadd];
	memcpy(csystem_data->country_code, cta_res + 13 + anspadd, 3);
	rdr_log(reader, "caid: %04X, acs: %x.%02x, country code: %c%c%c",
		reader->caid, cta_res[0 + anspadd], cta_res[1 + anspadd], cta_res[13 + anspadd], cta_res[14 + anspadd], cta_res[15 + anspadd]);

	/*
	 * Ascii/Hex-Serial
	 */
	if(csystem_data->t0 == 1)
	{
		irdeto_do_cmd(reader, sc_T0Ascii, 0x901D, cta_res, &cta_lr);
		int32_t anslength = cta_res[cta_lr - 1];
		sc_T0_Cmd[4] = anslength;
		reader_chk_cmd(sc_T0_Cmd, anslength + 2);
	}
	else
	{
		reader_chk_cmd(sc_T14GetASCIISerial, 22);
	}
	memcpy(buf, cta_res + anspadd, 10);
	buf[10] = 0;
	if(csystem_data->t0 == 1)
	{
		irdeto_do_cmd(reader, sc_T0Hex, 0x903E, cta_res, &cta_lr);
		int32_t anslength = cta_res[cta_lr - 1];
		sc_T0_Cmd[4] = anslength;
		reader_chk_cmd(sc_T0_Cmd, anslength + 2);
	}
	else
	{
		reader_chk_cmd(sc_T14GetHEXSerial, 18);
	}
	reader->nprov = cta_res[10 + anspadd];
	memcpy(reader->hexserial, cta_res + 12 + anspadd, 4);

	rdr_log_sensitive(reader, "providers: %d, ascii serial: {%s}, hex serial: {%02X%02X%02X}, hex base: {%02X}",
		reader->nprov, buf, reader->hexserial[0], reader->hexserial[1], reader->hexserial[2], reader->hexserial[3]);

	/*
	 * CardFile
	 */
	if(csystem_data->t0 == 1)
	{
		irdeto_do_cmd(reader, sc_T0CFile, 0x9049, cta_res, &cta_lr);
		int32_t anslength = cta_res[cta_lr - 1];
		sc_T0_Cmd[4] = anslength;
		reader_chk_cmd(sc_T0_Cmd, anslength + 2);
		sc_T0CFile[2] = 0x03;
		sc_T0CFile[5]++;
		irdeto_do_cmd(reader, sc_T0CFile, 0x9049, cta_res, &cta_lr);
		anslength = cta_res[cta_lr - 1];
		sc_T0_Cmd[4] = anslength;
		sc_T0_Cmd[2] = 0x03;
		reader_chk_cmd(sc_T0_Cmd, anslength + 2);
		sc_T0_Cmd[2] = 0x00;
	}
	else
	{
		for(sc_T14GetCardFile[2] = 2; sc_T14GetCardFile[2] < 4; sc_T14GetCardFile[2]++)
		{
			reader_chk_cmd(sc_T14GetCardFile, 0);
		}
	}

	/*
	 * CamKey
	 */
	if(csystem_data->t0 == 1)
	{
		int32_t i, crc = 61;
		crc ^= 0x01, crc ^= 0x02, crc ^= 0x09;
		crc ^= sc_T0CamKey[2], crc ^= sc_T0CamKey[3], crc ^= (sc_T0CamKey[4] + 1);

		for(i = 5; i < (int)sizeof(sc_T0CamKey) - 1; i++)
		{
			crc ^= sc_T0CamKey[i];
		}
		sc_T0CamKey[69] = crc;

		if(irdeto_do_cmd(reader, sc_T0CamKey, 0x9011, cta_res, &cta_lr))
		{
			rdr_log(reader, "You have a bad Cam Key set");
			return ERROR;
		}
		int32_t anslength = cta_res[cta_lr - 1];
		sc_T0_Cmd[4] = anslength;
		reader_chk_cmd(sc_T0_Cmd, anslength + 2);
	}
	// Dirty hack for Ziggo will be removed when optimum values are find on these T14 cards for v2 and triple
	// There are also other readers suffering from simmilar issue for those cards.
	else if(((reader->caid == 0x0604) || (reader->caid == 0x1722)) && (csystem_data->t0 == 0) && (reader->typ == R_SMART) && (reader->smart_type >= 2))
	{
		// Quick and dirty containment for the SmargoV2, Triple and Ziggo irdeto caid: 0604 using smartreader protocol
		// dirty hack ziggo nl card smartreader v2 and triple will be removed after findings optimum T14 values for v2 and triple
		// For some reason only 4 to 5 bytes are received, while 8 bytes are expected.
		int32_t rc;
		if(reader->caid == 0x1722)
		{
			rc = reader_cmd2icc(reader, sc_T14GetCamKey384DZ, sizeof(sc_T14GetCamKey384DZ), cta_res, &cta_lr);
		}
		else
		{
			rc = reader_cmd2icc(reader, sc_T14GetCamKey383C, sizeof(sc_T14GetCamKey383C), cta_res, &cta_lr);
		}
		rdr_log_dbg(reader, D_READER, "SmargoV2 camkey exchange containment: Ignoring returncode (%d), should have been 0.", rc);
		rdr_log_dbg(reader, D_READER, "In case cardinit NOK and/or no entitlements, retry by restarting ncam.");
	} // end dirty hack
	else
	{
		if(reader->caid == 0x1722)
		{
			reader_chk_cmd(sc_T14GetCamKey384DZ, 0);
		}
		else
		{
			reader_chk_cmd(sc_T14GetCamKey383C, 0);
		}
	}

	return irdeto_card_init_provider(reader);
}

int32_t irdeto_do_ecm(struct s_reader *reader, const ECM_REQUEST *er, struct s_ecm_answer *ea)
{
	def_resp;
	cta_lr = 0; // suppress compiler error
	static const uint8_t sc_T14EcmCmd[] = { 0x05, 0x00, 0x00, 0x02, 0x00 };
	uint8_t sc_T0Ecm[] = { 0xD5, 0x00, 0x00, 0x02, 0x00 };
	uint8_t sc_T0_Cmd[] = { T0ECM, 0xFE, 0x00, 0x00, 0x00 };
	uint8_t cta_cmd[MAX_ECM_SIZE];
	struct irdeto_data *csystem_data = reader->csystem_data;

	int32_t i = 0, anspadd = 0;
	if(csystem_data->t0 == 1)
	{
		int32_t crc = 63;
		anspadd = 8;
		sc_T0Ecm[4] = er->ecm[2] - 2;
		crc ^= 0x01;
		crc ^= 0x05;
		crc ^= sc_T0Ecm[2];
		crc ^= sc_T0Ecm[3];
		crc ^= (sc_T0Ecm[4] - 1);

		for(i = 6; i < er->ecm[2] + 4; i++)
		{
			crc ^= er->ecm[i];
		}

		memcpy(cta_cmd, sc_T0Ecm, sizeof(sc_T0Ecm));
		memcpy(cta_cmd + 5, er->ecm + 6, er->ecm[2] - 1);
		cta_cmd[er->ecm[2] + 2] = crc;

		irdeto_do_cmd(reader, cta_cmd, 0, cta_res, &cta_lr);
		int32_t anslength = cta_res[cta_lr - 1];

		sc_T0_Cmd[4] = anslength;

		int32_t try = 1;
		int32_t ret;
		do
		{
			if(try > 1)
			{
				snprintf(ea->msglog, MSGLOGSIZE, "%.22s reader_chk_cmd try nr %i", reader->label, try);
			}

			reader_chk_cmd(sc_T0_Cmd, anslength + 2);
			if((cta_res[2] == 0x9D) && (cta_res[3] == 0x00))
			{
				ret = 0;
			}
			else
			{
				ret = 1;
			}
			ret = ret || (cta_lr == 11);
			if(ret)
			{
				switch(cta_res[2])
				{
					case 0x26: // valid for V6 and V7 cards *26 rare case card gets locked if bad EMM being written
					{
						snprintf(ea->msglog, MSGLOGSIZE, "%.19s cardstatus: LOCKED", reader->label);
						return ERROR;
					}

					case 0x27: // valid for V6 and V7 cards Time sync EMMs
					{
						snprintf(ea->msglog, MSGLOGSIZE, "%.23s need global EMMs first", reader->label);
						return ERROR;
					}

					case 0x33: // valid for all cards *33 comes in 2 cases Either Card Requires to be init with Dynamic RSA AKA cmd28/A0 or Pairing Enabled
					{
						snprintf(ea->msglog, MSGLOGSIZE, "%.26s dynamic RSA init or pairing enabled", reader->label);
						return ERROR;
					}

					case 0x35: // valid for V6 and V7 cards Time sync EMMs
					{
						snprintf(ea->msglog, MSGLOGSIZE, "%.23s need global EMMs first", reader->label);
						return ERROR;
					}

					case 0x90: // valid for all cards
					{
						snprintf(ea->msglog, MSGLOGSIZE,"%.26s unsubscribed channel or chid missing", reader->label);
						return ERROR;
					}

					case 0x92: // valid for all cards
					{
						snprintf(ea->msglog, MSGLOGSIZE,"%.22s regional chid missing", reader->label);
						return ERROR;
					}

					case 0x9E: // valid for all cards *9E comes in 2 cases if card not fully updated OR if pairing Enabled
					{
						if(cta_res[3] == 0x65)
						{
							snprintf(ea->msglog, MSGLOGSIZE,"%.24s chipset pairing enabled", reader->label);
							return ERROR;
						}
						else
						{
							snprintf(ea->msglog, MSGLOGSIZE,"%.11s needs EMMs", reader->label);
							return ERROR;
						}
					}

					case 0xA0: // valid for all cards
					{
						snprintf(ea->msglog, MSGLOGSIZE,"%.17s surflock enabled", reader->label);
						return ERROR;
					}

					default: // all other error status
					{
						snprintf(ea->msglog, MSGLOGSIZE, "%.16s reader_chk_cmd [%d] %02x %02x", reader->label, cta_lr, cta_res[2], cta_res[3]);
						break;
					}
				}
			}
			try++;
		}
		while((try < 3) && (ret));

		if(ret)
		{
			return ERROR;
		}
	}
	else
	{
		memcpy(cta_cmd, sc_T14EcmCmd, sizeof(sc_T14EcmCmd));
		cta_cmd[4] = (er->ecm[2]) - 3;
		memcpy(cta_cmd + sizeof(sc_T14EcmCmd), &er->ecm[6], cta_cmd[4]);

		int32_t try = 1;
		int32_t ret;
		do
		{
			if(try > 1)
			{
				snprintf(ea->msglog, MSGLOGSIZE, "%.22s irdeto_do_cmd try nr %i", reader->label, try);
			}

			ret = (irdeto_do_cmd(reader, cta_cmd, 0x9D00, cta_res, &cta_lr));
			ret = ret || (cta_lr == 2);
			if(ret)
			{
				switch(cta_res[cta_lr - 2])
				{
					case 0x26: // valid for V6 and V7 cards *26 rare case card gets locked if bad EMM being written
					{
						snprintf(ea->msglog, MSGLOGSIZE, "%.19s cardstatus: LOCKED", reader->label);
						return ERROR;
					}

					case 0x27: // valid for V6 and V7 cards Time sync EMMs
					{
						snprintf(ea->msglog, MSGLOGSIZE, "%.23s need global EMMs first", reader->label);
						return ERROR;
					}

					case 0x33: // valid for all cards *33 comes in 2 cases Either Card Requires to be init with Dynamic RSA AKA cmd28/A0 or Pairing Enabled
					{
						snprintf(ea->msglog, MSGLOGSIZE, "%.26s dynamic RSA init or pairing enabled", reader->label);
						return ERROR;
					}

					case 0x35: // valid for V6 and V7 cards Time sync EMMs
					{
						snprintf(ea->msglog, MSGLOGSIZE, "%.23s need global EMMs first", reader->label);
						return ERROR;
					}

					case 0x90: // valid for all cards
					{
						snprintf(ea->msglog, MSGLOGSIZE,"%.26s unsubscribed channel or chid missing", reader->label);
						return ERROR;
					}

					case 0x92: // valid for all cards
					{
						snprintf(ea->msglog, MSGLOGSIZE,"%.22s regional chid missing", reader->label);
						return ERROR;
					}

					case 0x9E: // valid for all cards *9E comes in 2 cases if card not fully updated OR if pairing Enabled
					{
						if(cta_res[cta_lr - 1] == 0x65)
						{
							snprintf(ea->msglog, MSGLOGSIZE,"%.24s chipset pairing enabled", reader->label);
							return ERROR;
						}
						else
						{
							snprintf(ea->msglog, MSGLOGSIZE,"%.11s needs EMMs", reader->label);
							return ERROR;
						}
					}

					case 0xA0: // valid for all cards
					{
						snprintf(ea->msglog, MSGLOGSIZE,"%.17s surflock enabled", reader->label);
						return ERROR;
					}

					default: // all other error status
					{
						snprintf(ea->msglog, MSGLOGSIZE, "%.16s irdeto_do_cmd [%d] %02x %02x", reader->label, cta_lr, cta_res[cta_lr - 2], cta_res[cta_lr - 1]);
						break;
					}
				}
			}
			try++;
		}
		while((try < 3) && (ret));

		if(ret)
		{
			return ERROR;
		}
	}

	if((cta_res[3 + anspadd] == 0x36) || (cta_res[3 + anspadd] == 0x37) || (cta_res[3 + anspadd] == 0x24) || (cta_res[3 + anspadd] == 0x25))
	{
		snprintf(ea->msglog, MSGLOGSIZE, "cw needs tweaking");
	}

	ReverseSessionKeyCrypt(reader->boxkey, cta_res + 6 + anspadd);
	ReverseSessionKeyCrypt(reader->boxkey, cta_res + 14 + anspadd);
	memcpy(ea->cw, cta_res + 6 + anspadd, 16);
	return OK;
}

static int32_t irdeto_get_emm_type(EMM_PACKET *ep, struct s_reader *rdr)
{
	int32_t i, l = (ep->emm[3] & 0x07);
	int32_t base = (ep->emm[3] >> 3);
	char dumprdrserial[l * 3], dumpemmserial[l * 3];

	rdr_log_dbg(rdr, D_EMM, "Entered irdeto_get_emm_type ep->emm[3]=%02x", ep->emm[3]);

	switch(l)
	{
		case 0:
			// global emm, 0 bytes addressed
			ep->type = GLOBAL;
			rdr_log_dbg(rdr, D_EMM, "GLOBAL base = %02x", base);

			if(base & 0x10) // hex serial based?
			{
				if(base == rdr->hexserial[3]) // does base match?
				{
					return 1;
				}
				else
				{
					return 0; // base doesnt match!
				}
			}
			else
			{
				return 1;
			} // provider based, match all!

		case 2:
			// shared emm, 2 bytes addressed
			ep->type = SHARED;
			memset(ep->hexserial, 0, 8);
			memcpy(ep->hexserial, ep->emm + 4, l);
#ifdef WITH_DEBUG
			if(cs_dblevel & D_EMM)
			{
				cs_hexdump(1, rdr->hexserial, l, dumprdrserial, sizeof(dumprdrserial));
				cs_hexdump(1, ep->hexserial, l, dumpemmserial, sizeof(dumpemmserial));
			}
#endif
			rdr_log_dbg_sensitive(rdr, D_EMM, "SHARED l = %d ep = {%s} rdr = {%s} base = %02x",
					l, dumpemmserial, dumprdrserial, base);

			if(base & 0x10)
			{
				// hex addressed
				return ((base == rdr->hexserial[3]) && (!memcmp(ep->emm + 4, rdr->hexserial, l)));
			}
			else
			{
				if(!memcmp(ep->emm + 4, rdr->hexserial, l))
				{
					return 1;
				}

				// provider addressed
				for(i = 0; i < rdr->nprov; i++)
				{
					if((base == rdr->prid[i][0]) && (!memcmp(ep->emm + 4, &rdr->prid[i][1], l)))
					{
						return 1;
					}
				}
			}
			rdr_log_dbg(rdr, D_EMM, "neither hex nor provider addressed or unknown provider id");
			return 0;

		case 3:
			// unique emm, 3 bytes addressed
			ep->type = UNIQUE;
			memset(ep->hexserial, 0, 8);
			memcpy(ep->hexserial, ep->emm + 4, l);

#ifdef WITH_DEBUG
			if(cs_dblevel & D_EMM)
			{
				cs_hexdump(1, rdr->hexserial, l, dumprdrserial, sizeof(dumprdrserial));
				cs_hexdump(1, ep->hexserial, l, dumpemmserial, sizeof(dumpemmserial));
				rdr_log_dbg_sensitive(rdr, D_EMM, "UNIQUE l = %d ep = {%s} rdr = {%s} base = %02x",
					l, dumpemmserial, dumprdrserial, base);
			}
#endif
			if(base & 0x10) // unique hex addressed
			{
				return ((base == rdr->hexserial[3]) && (!memcmp(ep->emm + 4, rdr->hexserial, l)));
			}
			else
			{
				if(!memcmp(ep->emm + 4, rdr->hexserial, l))
				{
					return 1;
				}

				// unique provider addressed
				for(i = 0; i < rdr->nprov; i++)
				{
					if((base == rdr->prid[i][0]) && (!memcmp(ep->emm + 4, &rdr->prid[i][1], l)))
					{
						return 1;
					}
				}
			}
			rdr_log_dbg(rdr, D_EMM, "neither hex nor provider addressed or unknown provider id");
			return 0;

		default:
			ep->type = UNKNOWN;
			rdr_log_dbg(rdr, D_EMM, "UNKNOWN");
			return 1;
	}
}

static int32_t irdeto_get_emm_filter(struct s_reader *rdr, struct s_csystem_emm_filter **emm_filters, unsigned int *filter_count)
{
	if(*emm_filters == NULL)
	{
		const unsigned int max_filter_count = 3 + (rdr->nprov * 2);
		if(!cs_malloc(emm_filters, max_filter_count * sizeof(struct s_csystem_emm_filter)))
		{
			return ERROR;
		}

		struct s_csystem_emm_filter *filters = *emm_filters;
		*filter_count = 0;

		unsigned int idx = 0;

		filters[idx].type = EMM_GLOBAL;
		filters[idx].enabled = 1;
		filters[idx].filter[0] = 0x82;
		filters[idx].mask[0] = 0xFF;
		filters[idx].filter[1] = rdr->hexserial[3] << 3;
		filters[idx].mask[1] = 0xFF;
		idx++;

		filters[idx].type = EMM_UNIQUE;
		filters[idx].enabled = 1;
		filters[idx].filter[0] = 0x82;
		filters[idx].mask[0] = 0xFF;
		filters[idx].filter[1] = 0xFB;
		filters[idx].mask[1] = 0x07;
		memcpy(&filters[idx].filter[2], rdr->hexserial, 3);
		memset(&filters[idx].mask[2], 0xFF, 3);
		idx++;

		// Shared on Hex Serial only for Betacrypt
		if(caid_is_betacrypt(rdr->caid))
		{
			filters[idx].type = EMM_SHARED;
			filters[idx].enabled = 1;
			filters[idx].filter[0] = 0x82;
			filters[idx].mask[0] = 0xFF;
			filters[idx].filter[1] = 0xFA;
			filters[idx].mask[1] = 0x07;
			memcpy(&filters[idx].filter[2], rdr->hexserial, 2);
			memset(&filters[idx].mask[2], 0xFF, 2);
			idx++;
		}

		int32_t i;
		for(i = 0; i < rdr->nprov; i++)
		{
			filters[idx].type = EMM_UNIQUE;
			filters[idx].enabled = 1;
			filters[idx].filter[0] = 0x82;
			filters[idx].mask[0] = 0xFF;
			filters[idx].filter[1] = 0xFB;
			filters[idx].mask[1] = 0x07;
			memcpy(&filters[idx].filter[2], &rdr->prid[i][1], 3);
			memset(&filters[idx].mask[2], 0xFF, 3);
			idx++;

			filters[idx].type = EMM_SHARED;
			filters[idx].enabled = 1;
			filters[idx].filter[0] = 0x82;
			filters[idx].mask[0] = 0xFF;
			filters[idx].filter[1] = 0xFA;
			filters[idx].mask[1] = 0x07;
			memcpy(&filters[idx].filter[2], &rdr->prid[i][1], 2);
			memset(&filters[idx].mask[2], 0xFF, 2);
			idx++;
		}

		*filter_count = idx;
	}

	return OK;
}

static int32_t irdeto_get_tunemm_filter(struct s_reader *rdr, struct s_csystem_emm_filter **emm_filters, unsigned int *filter_count)
{
	if(*emm_filters == NULL)
	{
		const unsigned int max_filter_count = 3;
		if(!cs_malloc(emm_filters, max_filter_count * sizeof(struct s_csystem_emm_filter)))
		{
			return ERROR;
		}

		struct s_csystem_emm_filter *filters = *emm_filters;
		*filter_count = 0;

		unsigned int idx = 0;

		filters[idx].type = EMM_GLOBAL;
		filters[idx].enabled = 1;
		filters[idx].filter[0] = 0x82;
		filters[idx].mask[0] = 0xFF;
		idx++;

		filters[idx].type = EMM_SHARED;
		filters[idx].enabled = 1;
		filters[idx].filter[0] = 0x83;
		filters[idx].filter[1] = rdr->hexserial[1];
		filters[idx].filter[2] = rdr->hexserial[0];
		filters[idx].filter[3] = 0x10;
		filters[idx].filter[4] = 0x00;
		filters[idx].filter[5] = 0x10;
		memset(&filters[idx].mask[0], 0xFF, 6);
		idx++;

		filters[idx].type = EMM_UNIQUE;
		filters[idx].enabled = 1;
		filters[idx].filter[0] = 0x83;
		filters[idx].filter[1] = rdr->hexserial[1];
		filters[idx].filter[2] = rdr->hexserial[0];
		filters[idx].filter[3] = 0x10;
		filters[idx].filter[4] = rdr->hexserial[2];
		filters[idx].filter[5] = 0x00;
		memset(&filters[idx].mask[0], 0xFF, 6);
		idx++;

		*filter_count = idx;
	}

	return OK;
}

void irdeto_add_emm_header(EMM_PACKET *ep)
{
	uint8_t bt_emm[MAX_EMM_SIZE];
	static const char *typtext[] = { "unknown", "unique", "shared", "global" };
	memset(bt_emm, 0, sizeof(bt_emm));

	ep->type = UNKNOWN;
	if((ep->emm[0] == 0x83) && (ep->emm[5] == 0x10))
	{
		if(ep->emm[7] == 0x00)
		{
			ep->type = UNIQUE;
		}
		else
		{
			ep->type = SHARED;
		}
	}
	else
	{
		if(ep->emm[0] == 0x82)
		{
			ep->type = GLOBAL;
		}
	}

	if((ep->type != UNKNOWN) && (ep->emmlen == 142))
	{
		cs_log_dbg(D_EMM, "[TUN_EMM] Type: %s - rewriting header", typtext[ep->type]);
	}
	else
	{
		return;
	}

	// BETACRYPT/IRDETO EMM HEADER:
	static uint8_t headerD0[6] = { 0x82, 0x70, 0x89, 0xd0, 0x01, 0x00 }; // GLOBAL
	static uint8_t headerD2[8] = { 0x82, 0x70, 0x8b, 0xd2, 0x00, 0x00, 0x01, 0x00 }; // SHARED
	static uint8_t headerD3[9] = { 0x82, 0x70, 0x8c, 0xd3, 0x00, 0x00, 0x00, 0x01, 0x00 }; // UNIQUE

	switch(ep->type)
	{
		case UNIQUE:
			memcpy(bt_emm, headerD3, sizeof(headerD3));
			memcpy(bt_emm + sizeof(headerD3), ep->emm + 8, ep->emmlen - 8);
			bt_emm[4] = ep->emm[4];
			bt_emm[5] = ep->emm[3];
			bt_emm[6] = ep->emm[6];
			ep->emmlen = 143;
			break;

		case SHARED:
			memcpy(bt_emm, headerD2, sizeof(headerD2));
			memcpy(bt_emm + sizeof(headerD2), ep->emm + 8, ep->emmlen - 8);
			bt_emm[4] = ep->emm[4];
			bt_emm[5] = ep->emm[3];
			ep->emmlen = 142;
			break;

		case GLOBAL:
			memcpy(bt_emm, headerD0, sizeof(headerD0));
			memcpy(bt_emm + sizeof(headerD0), ep->emm + 8, ep->emmlen - 8);
			ep->emmlen = 140;
			break;
	}
	memcpy(ep->emm, bt_emm, sizeof(bt_emm));
}

#define ADDRLEN 4 // Address length in EMM commands

static int32_t irdeto_do_emm(struct s_reader *reader, EMM_PACKET *ep)
{
	def_resp;
	static const uint8_t sc_T14EmmCmd[] = { 0x01, 0x00, 0x00, 0x00, 0x00 };
	static uint8_t sc_T0Emm[] = { 0xD1, 0x00, 0x00, 0x00, 0x00 };
	uint8_t sc_T0_Cmd[] = { T0EMM, 0xFE, 0x00, 0x00, 0x00 };
	struct irdeto_data *csystem_data = reader->csystem_data;
	uint8_t cta_cmd[272];

	if(ep->emm[0] != 0x82)
	{
		rdr_log_dbg(reader, D_EMM, "Invalid EMM: Has to start with 0x82, but starts with %02x!", ep->emm[0]);
		return ERROR;
	}

	int32_t i, l = (ep->emm[3] & 0x07), ok = 0;
	int32_t mode = (ep->emm[3] >> 3);
	uint8_t *emm = ep->emm;

	if(mode & 0x10)
	{
		// hex addressed
		ok = ((mode == reader->hexserial[3]) && ((!l) || (!memcmp(&emm[4], reader->hexserial, l))));
	}
	else
	{
		ok = !memcmp(&emm[4], reader->hexserial, l);

		// provider addressed
		for(i = 0; i < reader->nprov && !ok; i++)
		{
			ok = ((mode == reader->prid[i][0]) && ((!l) || (!memcmp(&emm[4], &reader->prid[i][1], l))));
		}
	}

	if(ok)
	{
		l++;
		if(l <= ADDRLEN)
		{
			if(csystem_data->t0 == 1)
			{
				int32_t dataLen = 0;

				if(ep->type == UNIQUE)
				{
					dataLen = ep->emm[2] - 1;
				}
				else
				{
					dataLen = ep->emm[2];
				}

				if((dataLen < 7) || (dataLen > ((int32_t)sizeof(ep->emm) - 6)) || (dataLen > ((int32_t)sizeof(cta_cmd) - 9)))
				{
					rdr_log_dbg(reader, D_EMM, "dataLen %d seems wrong, faulty EMM?", dataLen);
					return ERROR;
				}

				if(ep->type == GLOBAL)
				{
					dataLen += 2;
				}

				int32_t crc = 63;
				sc_T0Emm[4] = dataLen;
				memcpy(&cta_cmd, sc_T0Emm, sizeof(sc_T0Emm));
				crc ^= 0x01;
				crc ^= 0x01;
				crc ^= 0x00;
				crc ^= 0x00;
				crc ^= 0x00;
				crc ^= (dataLen - 1);
				memcpy(&cta_cmd[5], &ep->emm[3], 10);

				if(ep->type == UNIQUE)
				{
					memcpy(&cta_cmd[9], &ep->emm[9], dataLen - 4);
				}
				else
				{
					if(ep->type == GLOBAL)
					{
						memcpy(&cta_cmd[9], &ep->emm[6], 1);
						memcpy(&cta_cmd[10], &ep->emm[7], dataLen - 6);
						// cta_cmd[9]=0x00;
					}
					else
					{
						memcpy(&cta_cmd[9], &ep->emm[8], dataLen - 4);
					}
				}

				for(i = 5; i < dataLen + 4; i++)
				{
					crc ^= cta_cmd[i];
				}

				cta_cmd[dataLen - 1 + 5] = crc;
				irdeto_do_cmd(reader, cta_cmd, 0, cta_res, &cta_lr);
				int32_t anslength = cta_res[cta_lr - 1];
				sc_T0_Cmd[4] = anslength;
				reader_chk_cmd(sc_T0_Cmd, anslength + 2);

				rdr_log_dbg(reader, D_EMM,"response %02X %02X %02X %02X %02X (%s)",
					cta_res[0], cta_res[1], cta_res[2], cta_res[3], cta_res[4],
					(((cta_res[2] == 0) || (cta_res[2] == 0x7B) || (cta_res[2] == 0x7C)) ? "OK" : "ERROR"));

				if((cta_res[2] == 0x7B) || (cta_res[2] == 0x7C)) // chid already written or chid already up to date
				{
					return SKIPPED;
				}

				if(cta_res[2] == 0x00)
				{
					return OK;
				}
				return ERROR; // all other
			}
			else // T14 protocol based cards
			{
				const int32_t dataLen = SCT_LEN(emm) - 5 - l; // sizeof of emm bytes (nanos)

				if((dataLen < 1) || (dataLen > ((int32_t)sizeof(ep->emm) - 5 - l))
					|| (dataLen > ((int32_t)sizeof(cta_cmd) - (int32_t)sizeof(sc_T14EmmCmd) - ADDRLEN)))
				{
					rdr_log_dbg(reader, D_EMM, "dataLen %d seems wrong, faulty EMM?", dataLen);
					return ERROR;
				}

				uint8_t *ptr = cta_cmd;
				memcpy(ptr, sc_T14EmmCmd, sizeof(sc_T14EmmCmd));	// copy card command
				ptr[4] = dataLen + ADDRLEN;					// set card command emm size
				ptr += sizeof(sc_T14EmmCmd);
				emm += 3;
				memset(ptr, 0, ADDRLEN);					// clear addr range
				memcpy(ptr, emm, l);						// copy addr bytes
				ptr += ADDRLEN;
				emm += l;
				memcpy(ptr, &emm[2], dataLen);				// copy emm bytes]
				irdeto_do_cmd(reader, cta_cmd, 0, cta_res, &cta_lr);

				rdr_log_dbg(reader, D_EMM,"response %02X %02X %02X %02X %02X (%s)",
					cta_res[0], cta_res[1], cta_res[2], cta_res[3], cta_res[4],
					(((cta_res[cta_lr-2] == 0) || (cta_res[cta_lr-2] == 0x7B) || (cta_res[cta_lr-2] == 0x7C)) ? "OK" : "ERROR"));

				if((cta_res[cta_lr-2] == 0x7B) || (cta_res[cta_lr-2] == 0x7C)) // chid already written or chid already up to date
				{
					return SKIPPED;
				}

				if(cta_res[cta_lr-2] == 0x00)
				{
					return OK;
				}

				return ERROR; // all other
			}
		}
		else
		{
			rdr_log_dbg(reader, D_EMM, "addrlen %d > %d", l, ADDRLEN);
			return ERROR;
		}
	}
	else
	{
		rdr_log_dbg(reader, D_EMM, "EMM skipped since its hexserial or base doesnt match with this card!");
		return SKIPPED;
	}
}

static int32_t irdeto_card_info(struct s_reader *reader)
{
	def_resp;
	int32_t i, p;
	struct irdeto_data *csystem_data = reader->csystem_data;

	cs_clear_entitlement(reader); // reset the entitlements

	uint8_t sc_T14GetChannelIds[] = { 0x02, 0x04, 0x00, 0x00, 0x01, 0x00 };
	uint8_t sc_T0Code[] = { 0xD2, 0x16, 0x00, 0x00, 0x01 , 0x37 };
	uint8_t sc_T0Prid[] = { 0xD2, 0x08, 0x00, 0x00, 0x02, 0x00, 0x00 };
	uint8_t sc_T0_Cmd[] = { T0GET, 0xFE, 0x00, 0x00, 0x00 };

	/*
	 * ContryCode2
	 */
	int32_t anspadd = 0;
	if(csystem_data->t0 == 1)
	{
		anspadd = 8;
		reader_chk_cmd(sc_T0Code, 0);
		int32_t anslength = cta_res[cta_lr - 1];
		sc_T0_Cmd[4] = anslength;
		reader_chk_cmd(sc_T0_Cmd, anslength + 2);
	}
	else
	{
		reader_chk_cmd(sc_T14GetCountryCode2, 0);
	}

	if(((cta_lr > 9) && !(cta_res[cta_lr - 2] | cta_res[cta_lr - 1])) || (csystem_data->t0 == 1))
	{
		rdr_log_dbg(reader, D_READER, "max chids: %d, %d, %d, %d",
				cta_res[6 + anspadd], cta_res[7 + anspadd], cta_res[8 + anspadd], cta_res[9 + anspadd]);

		/*
		 * Provider 2
		 */
		for(i = p = 0; i < reader->nprov; i++)
		{
			int32_t j, k, chid, first = 1;
			char t[32];

			if(reader->prid[i][4] != 0xff)
			{
				p++;
				sc_T0Prid[3] = i;
				sc_T14GetChannelIds[3] = i; // provider at index i
				j = 0;

				// for (j=0; j<10; j++) => why 10 .. do we know for sure the there are only 10 chids !!!
				// shouldn't it me the max chid value we read above ?!

				while(1) // will exit if cta_lr < 61 .. which is the correct break condition.
				{
					if(csystem_data->t0 == 1)
					{
						int32_t crc = 63;
						sc_T0Prid[5] = j;
						crc ^= 0x01;
						crc ^= 0x02;
						crc ^= 0x04;
						crc ^= sc_T0Prid[2];
						crc ^= sc_T0Prid[3];
						crc ^= (sc_T0Prid[4] - 1);
						crc ^= sc_T0Prid[5];
						sc_T0Prid[6] = crc;
						irdeto_do_cmd(reader, sc_T0Prid, 0x903C, cta_res, &cta_lr);
						int32_t anslength = cta_res[cta_lr - 1];

						if(anslength == 0x09)
						{
							break;
						}

						sc_T0_Cmd[4] = anslength;
						reader_chk_cmd(sc_T0_Cmd, anslength + 2);

						if(cta_res[10] == 0xFF)
						{
							break;
						}

						cta_res[cta_lr - 3] = 0xff;
						cta_res[cta_lr - 2] = 0xff;
						cta_res[cta_lr - 1] = 0xff;
						anspadd = 8;
					}
					else
					{
						sc_T14GetChannelIds[5] = j; // chid at index j for provider at index i
						reader_chk_cmd(sc_T14GetChannelIds, 0);
					}

					// if (cta_lr<61) break; // why 61 (0 to 60 in steps of 6 .. is it 10*6 from the 10 in the for loop ?
					// what happen if the card only send back.. 9 chids (or less)... we don't see them
					// so we should check whether or not we have at least 6 bytes (1 chid).
					if(cta_lr < 6)
					{
						break;
					}

					for(k = 0 + anspadd; k < cta_lr; k += 6)
					{
						chid = b2i(2, cta_res + k);
						if(chid && chid != 0xFFFF)
						{
							time_t date, start_t, end_t;

							start_t = chid_date(reader, date = b2i(2, cta_res + k + 2), t, 16);
							end_t = chid_date(reader, date + cta_res[k + 4], t + 16, 16);

							// todo: add entitlements to list but produces a warning related to date variable
							cs_add_entitlement(reader, reader->caid, b2i(3, &reader->prid[i][1]), chid, 0, start_t, end_t, 3, 1);

							if(first)
							{
								rdr_log_sensitive(reader, "entitlements for provider: %d, id: {%06X}", p, b2i(3, &reader->prid[i][1]));
								first = 0;
							}
							rdr_log(reader, "chid: %04X, date: %s - %s", chid, t, t + 16);
						}
					}
					j++;
				}
			}
		}
	}
	rdr_log(reader, "ready for requests");
	return OK;
}

const struct s_cardsystem reader_irdeto =
{
	.desc              = "irdeto",
	.caids             = (uint16_t[]){ 0x06, 0x17, 0 },
	.do_emm            = irdeto_do_emm,
	.do_ecm            = irdeto_do_ecm,
	.card_info         = irdeto_card_info,
	.card_init         = irdeto_card_init,
	.get_emm_type      = irdeto_get_emm_type,
	.get_emm_filter    = irdeto_get_emm_filter,
	.get_tunemm_filter = irdeto_get_tunemm_filter,
};

#endif
