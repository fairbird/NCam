#define MODULE_LOG_PREFIX "cardlist"
#include "globals.h"
#ifdef WITH_CARDLIST
#include "cardlist.h"
#include "ncam-aes.h"
#include "ncam-chk.h"
#include "ncam-conf-chk.h"
#include "ncam-conf-mk.h"
#include "ncam-work.h"
#include "ncam-string.h"
static void info(char *c, char *i) { memcpy(c, i, cs_strlen(i)); }
static uint8_t card_system(char *atr)
{
	if(atr[7] == 0x31 && atr[9] == 0x30 && atr[10] == 0x30) // Seca
		return 0x01;
	else if(atr[7] == 0x38) // Viaccess
		return 0x05;
	else if(atr[7] == 0x32) // Cryptoworks (irdeto)
		return 0x0D;
	else if((atr[9] == 0x30 && atr[10] == 0x45 && atr[42] == 0x32) || (atr[9] == 0x32 && atr[10] == 0x31)) // Irdeto
		return 0x06;
	else if(atr[9] == 0x32 && atr[10] == 0x35) // Videoguard2
		return 0x09;
	/*else if((atr[7] == 0x30 && atr[9] == 0x33) || atr[7] == 0x34) // Conax
		return 0x0B;*/
	else if((atr[7] == 0x35) || (atr[9] == 0x30 && atr[10] == 0x45 && atr[42] == 0x30)) // Nagra + Betacrypt 0x17
		return 0x18;
	/*else if(atr[9] == 0x31 && atr[10] == 0x32) // DreCrypt
		return 0x4A;
	else if(atr[3] == 0x32 && atr[4] == 0x30) // Bulcrypt
		return 0x55;
	else if((atr[6] == 0x30 && atr[7] == 0x31) || (atr[3] == 0x45 && atr[4] == 0x39)) // Griffin
		return 0;*/
	return 0;
}
static void fn(char *value, uint8_t *var, long size)
{
	int32_t len = cs_strlen(value);
	if(len == size * 2)
	{
		if(!key_atob_l(value, var, len))
		{
			var[size] = 0x01;
		}
	}
}
#if defined(READER_IRDETO) || defined(READER_CRYPTOWORKS)
static void cardlist_do_reset(struct s_reader *reader)
{
	if(!reader->caid && !reader->cardlist_reset)
	{
		reader->cardlist_reset = 1;
		add_job(reader->client, 10, NULL, 0);
	}
	else if(reader->caid)
	{
		reader->cardlist_reset = 0;
	}
}
#endif
/*
Bit pattern for save/block EMMs:
EMM_UNIQUE: 1
EMM_SHARED: 2
EMM_GLOBAL: 4
EMM_UNKNOWN: 8
SUM EMM for Value
*/
struct atrlist current;

void findatr(struct s_reader *reader)
{
	if(!reader->cardlist)
	{
		return;
	}
#if defined(READER_SECA) || defined(READER_VIACCESS) || defined(READER_IRDETO) || defined(READER_CRYPTOWORKS) || defined(READER_NAGRA) || defined(READER_VIDEOGUARD) || defined(READER_NAGRA_MERLIN)
	char *caid = NULL, *ident = NULL, *auprovid = NULL, *ecmwhitelist = NULL, *ecmheaderwhitelist = NULL, *disablecrccws_only_for = NULL;
	char *rsakey = NULL, *deskey = NULL, *boxkey = NULL, *pincode = NULL, *aeskeys = NULL;
	char *boxid = NULL, *ins7E = NULL, *ins7E11 = NULL, *ins2e06 = NULL, *k1_generic = NULL, *k1_unique = NULL;
#ifdef READER_NAGRA_MERLIN
	char *mod1 = NULL, *data50 = NULL, *mod50 = NULL, *key60 = NULL, *exp60 = NULL, *nuid = NULL, *cwekey = NULL;
#endif
#endif
	//char testatr[80] = "3F 77 18 00 00 C2 EB 45 02 6C 90 00";
	//memcpy(current.atr, testatr, cs_strlen(testatr));
	switch (card_system(current.atr))
	{
	case 0x01:
#ifdef READER_SECA
		if(strncmp(current.atr, "3B F7 11 00 01 40 96 70 70 0A 0E 6C B6 D6", 42) == 0)
		{
			/* more providers: ? */
			info(current.providername, "Canal Digitaal (NL)");
			caid = "0100";
			reader->ratelimitecm = 4;
			reader->ratelimittime = 9000;
			reader->saveemm = 3;
			reader->blockemm = 12;
		}
#else
		info(current.info, "SECA not built in!");
#endif
		break;
	case 0x05:
#ifdef READER_VIACCESS
		if(strncmp(current.atr, "3F 77 18 00 00 C2 EB 41 02 6C 90 00", 35) == 0)
		{
			/* Mega Elite Royale V5 (INT) (0500:043800,050F00) */
			info(current.providername, "Redlight Mega Elite");
			deskey = "";
			boxkey = "";
			pincode = "0000";
			reader->blockemm = 12;
		}
		else if(strncmp(current.atr, "3F 77 18 00 00 D3 8A 42 01 64 90 00", 35) == 0)
		{
			/* ? and TNTSAT V5 */
			info(current.providername, "Redlight Mega Royale");
			deskey = "";
			boxkey = "";
			pincode = "0000";
			reader->blockemm = 12;
		}
		else if(strncmp(current.atr, "3F 77 18 00 00 C2 7A 41 02 68", 29) == 0)
		{
			/* more providers: FRANSAT (FR) V4 (0500:041900), SRF (CH) V4 (0500:040810) */
			info(current.providername, "SRG v4");
			reader->blockemm = 8;
		}
		else if(strncmp(current.atr, "3F 77 18 00 00 C2 7A 44 02 68", 29) == 0)
		{
			/* more providers: FRANSAT (FR) V5 (0500:041950), Bis TV V4 (FR) (0500:042800) */
			info(current.providername, "SRG v5");
			reader->read_old_classes = 0;
			reader->blockemm = 8;
		}
		else if(strncmp(current.atr, "3F 77 18 00 00 C2 EB 41 02 6C", 29) == 0 ||
				 strncmp(current.atr, "3F 77 18 00 00 C2 EB 45 02 6C 90 00", 35) == 0)
		{
			/* more providers: TNTSAT V4/V5 (FR) (0500:030B00), NTV+ (RU) V6 (0500:050100), SRF (CH) V5 (0500:050800), TVSAT AFRICA (INT) V5 (0500:042840) */
			info(current.providername, "TNT Viaccess v5");
			caid = "0500";
			ident = "0500:030B00,FFF400";
			auprovid = "030B00";
			//ecmwhitelist = "";
			deskey = "";
			boxkey = "";
			aeskeys = ""; // warning: do not use public aeskeys, as the service provider may block the card via public aeskeys
			reader->audisabled = 1;
			reader->cachemm = 1;
			reader->rewritemm = 3;
			reader->logemm = 2;
			reader->deviceemm = 0;
		}
		else if(strncmp(current.atr, "3F 77 18 00 00 D3 8A 40 01 64", 29) == 0)
		{
			/* more providers: TNTSAT V6 (FR) (0500:030B00), CANAL+/CANAL (FR) V6 (0500:032830), ORANGE SAT (FR) V6 (0500:032900), SRF (CH) V6 (0500:060200), TELESAT (ex MOBISTAR) (BE) V6 (0500:051900) */
			info(current.providername, "TNT Viaccess v6");
			caid = "0500";
			ident = "0500:030B00,FFF400";
			auprovid = "030B00";
			//ecmwhitelist = "";
			deskey = "";
			boxkey = "";
			aeskeys = ""; // warning: do not use public aeskeys, as the service provider may block the card via public aeskeys
			reader->audisabled = 1;
			reader->cachemm = 1;
			reader->rewritemm = 3;
			reader->logemm = 2;
			reader->deviceemm = 0;
		}
#else
		info(current.info, "VIACCESS not built in!");
#endif
		break;
	case 0x06:
#ifdef READER_IRDETO
		if(strncmp(current.atr, "3B 9F 21 0E 49 52 44 45 54 4F 20 41 43 53 20 56 35 2E 38 95", 59) == 0)
		{
			/* Ziggo NL (0604:0000) ? */
			info(current.providername, "Ziggo NL");
			rsakey = "";
			boxkey = "";
			reader->blockemm = 12;
		}
		if(strncmp(current.atr, "3B 9F 21 0E 49 52 44 45 54 4F 20 41 43 53 20 56 35 2E 37 9A", 59) == 0)
		{
			if(chk_caid_rdr(reader, 0x603) || chk_ctab_ex(0x603, &reader->ctab))
			{
				/* Al Jazeera (QA)(0603:088124) */
				info(current.providername, "Al Jazeera");
				//caid = "0603";
				//ident = "0603:088124";
				//auprovid = "088124";
				//ecmwhitelist = "53,5D,61";
				//reader->blockemm = 12;
			}
			else if(chk_caid_rdr(reader, 0x652) || chk_ctab_ex(0x652, &reader->ctab))
			{
				/* Raduga TV (RU) (0652:FFFFFF) */
				info(current.providername, "Raduga TV");
				caid = "0652";
				//ident = "0652:04c319,ffffff";
				//auprovid = "04c319";
				ecmwhitelist = "3C";
				rsakey = "";
				boxkey = "";
				reader->cachemm = 1;
				reader->rewritemm = 3;
				reader->logemm = 2;
				reader->deviceemm = 0;
				reader->blockemm = 12;
			}
			else
			{
				cardlist_do_reset(reader);
			}
		}
#else
		info(current.info, "IRDETO not built in!");
#endif
		break;
	case 0x0D:
#if defined(READER_CRYPTOWORKS) || defined(READER_IRDETO)
#ifdef READER_CRYPTOWORKS
		if(strncmp(current.atr, "3B 78 12 00 00 65 C4 05 FF 8F F1 90 00", 38) == 0)
		{
			// ARENA (0D22)
			info(current.providername, "ARENA");
			caid = "0D22";
			ident = "0D22:000001,000002,000003,00004";
			//auprovid = "000001";
			reader->cachemm = 1;
			reader->rewritemm = 3;
			reader->logemm = 2;
			reader->deviceemm = 0;
			reader->blockemm = 12;
		}
		else
#endif
			if(strncmp(current.atr, "3B 78 12 00 00 54 C4 03 00 8F F1 90 00", 38) == 0)
		{
#if !defined(READER_CRYPTOWORKS) && defined(READER_IRDETO)
			reader->force_irdeto = 1;
#endif
			/* more providers: ? */
			if(!reader->force_irdeto)
			{
#ifdef READER_CRYPTOWORKS
				if(chk_caid_rdr(reader, 0xD95) || chk_ctab_ex(0xD95, &reader->ctab))
				{
					// ORF (AT) (0D95)
					info(current.providername, "ORF ICE CW-Mode");
					caid = "0D95";
					ident = "0D95:000004,000008,00000C,000010";
					auprovid = "000004";
					ecmwhitelist = "80,B8,F0";
					ecmheaderwhitelist = "8070ED81FF0000E880D500010006,8170ED81FF0000E880D500010006,8070B581FF0000B0809D00010006,8170B581FF0000B0809D00010006";
					reader->cachemm = 1;
					reader->rewritemm = 3;
					reader->logemm = 2;
					reader->deviceemm = 0;
					reader->blockemm = 12;
				}
				else if(chk_caid_rdr(reader, 0xD96) || chk_ctab_ex(0xD96, &reader->ctab))
				{
					// Skylink ICE (DE) (0D96)
					info(current.providername, "Skylink ICE CW-Mode");
					caid = "0D96";
					ident = "0D96:000004,000008,00000C,000010";
					auprovid = "000004";
					ecmwhitelist = "80,B8,7B,7C";
					reader->cachemm = 1;
					reader->rewritemm = 3;
					reader->logemm = 2;
					reader->deviceemm = 0;
					reader->blockemm = 12;
					reader->needsglobalfirst = 1;
				}
				else if(chk_caid_rdr(reader, 0xD97) || chk_ctab_ex(0xD97, &reader->ctab) ||
					 chk_caid_rdr(reader, 0x653) || chk_ctab_ex(0x653, &reader->ctab))
				{
					// UPC (0D97/SAT 0.8W)
					info(current.providername, "UPC ICE CW-Mode");
					caid = "0D97";
					ident = "0D97:000004,000008,00000C,000010";
					auprovid = "000004";
					ecmwhitelist = "B8,F0,80";
					ecmheaderwhitelist = "80707D81FF0000788065,81707D81FF0000788065,8070B581FF0000B0809D,8170B581FF0000B0809D,8070ED81FF0000E880D5,8170ED81FF0000E880D5";
					reader->cachemm = 1;
					reader->rewritemm = 3;
					reader->logemm = 2;
					reader->deviceemm = 0;
					reader->blockemm = 12;
				}
				else
				{
					cardlist_do_reset(reader);
				}
#else
				info(current.info, "CRYPTOWORKS not built in!");
#endif
			}
			else
			{
#ifdef READER_IRDETO
				if(chk_caid_rdr(reader, 0x624) || chk_ctab_ex(0x624, &reader->ctab))
				{
					/* Skylink (CZ) (0624:FFFFFF) */
					info(current.providername, "Skylink (CZ)");
					caid = "0624";
					ident = "0624:000000";
					ecmwhitelist = "3C,3E,41,55,5F,59,63,69,4F,6D,45,51,45,47";
					reader->cachemm = 1;
					reader->rewritemm = 3;
					reader->logemm = 15;
					reader->deviceemm = 0;
					reader->blockemm = 12;
					rsakey = "";
					boxkey = "";
				}
				else if(chk_caid_rdr(reader, 0x650) || chk_ctab_ex(0x650, &reader->ctab))
				{
					/* ORF-Digital HD & Au-Sat Plus ohne HD (AT) (0650:000000) */
					info(current.providername, "ORF ICE Irdeto-Mode");
					caid = "0650";
					reader->cachemm = 1;
					reader->rewritemm = 3;
					reader->logemm = 15;
					reader->deviceemm = 0;
					reader->blockemm = 12;
					rsakey = "";
					boxkey = "";
				}
				else if(chk_caid_rdr(reader, 0x653) || chk_ctab_ex(0x653, &reader->ctab) ||
					 chk_caid_rdr(reader, 0xD97) || chk_ctab_ex(0xD97, &reader->ctab))
				{
					/* UPC (0653:FFFFFF) */
					info(current.providername, "UPC ICE Irdeto-Mode");
					caid = "0653";
					ident = "0653:000000";
					ecmwhitelist = "3C";
					reader->cachemm = 1;
					reader->rewritemm = 3;
					reader->logemm = 15;
					reader->deviceemm = 0;
					reader->blockemm = 12;
					rsakey = "";
					boxkey = "";
				}
				else
				{
					cardlist_do_reset(reader);
				}
#else
				info(current.info, "IRDETO not built in!");
#endif
			}
#else
		info(current.info, "CRYPTOWORKS not built in!");
#endif
		}
		break;
	case 0x18:
#ifdef READER_NAGRA
		if(strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 47 00 44 4E 41 53 50 31 34 32 20 52 65 76 47 30 32 16", 80) == 0)
		{
			/* more providers: */
			if(chk_caid_rdr(reader, 0x1801))
			{
				info(current.providername, "DreamTV N3 (1801/Sat)");
				return;
			}
			else if(chk_caid_rdr(reader, 0x1802))
			{
				info(current.providername, "DigiTV Hu/Ro (1802/Sat)");
				return;
			}
			else if(chk_caid_rdr(reader, 0x1803))
			{
				info(current.providername, "Polsat(PL) (1803/Sat)");
				return;
			}
			else if(chk_caid_rdr(reader, 0x1815))
			{
				info(current.providername, "UPC (1815/Sat)");
				caid = "1815";
				ident = "1815:B801,B901";
				auprovid = "00B801";
				ecmwhitelist = "92";
				reader->blockemm = 12;
			}
		}
		else if(strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 47 00 4E 43 4D 45 44 36 30 31 20 52 65 76 4D 30 36 11", 80) == 0)
		{
			/* more providers: */
			if(chk_caid_rdr(reader, 0x1802))
			{
				info(current.providername, "Mediaset (IT) (1802)");
				return;
			}
			else if(chk_caid_rdr(reader, 0x1804))
			{
				info(current.providername, "DreamTV N3 (1801/Sat)");
				return;
			}
			else if(chk_caid_rdr(reader, 0x1805))
			{
				info(current.providername, "Mediaset (IT) (1805)");
				return;
			}
		}
		else if(strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FF 47 00 54 49 47 45 52 30 30 33 20 52 65 76 32 35 30 64", 80) == 0 ||
				 strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 47 00 54 49 47 45 52 36 30 31 20 52 65 76 4D 38 37 14", 80) == 0 ||
				 strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 47 00 54 49 47 45 52 36 30 31 20 52 65 76 4D 32 30 19", 80) == 0)
		{
			/* Tivusat (IT) (183x/Sat) */
			info(current.providername, "Tivusat 183D / 183E / 1807");
			auprovid = "005411";
			ecmwhitelist = "91";
			reader->cachemm = 1;
			reader->rewritemm = 3;
			reader->logemm = 2;
			reader->deviceemm = 0;
			reader->blockemm = 8;
			rsakey = "";
			reader->blockemm = 8;
		}
		else if(strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 47 00 44 4E 41 53 50 31 31 30 20 52 65 76 41 32 32 15", 80) == 0 ||
				 strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 47 00 44 4E 41 53 50 31 34 32 20 52 65 76 47 30 36 12", 80) == 0)
		{
			/* Unitymedia UM01 and UM02 */
			info(current.providername, "Unitymedia UM01 / UM02");
			rsakey = "";
			boxkey = "";
			reader->blockemm = 12;
		}
		else if(strncmp(current.atr, "3B 9F 21 0E 49 52 44 45 54 4F 20 41 43 53 03 84 55 FF 80 6D", 59) == 0)
		{
			/* more providers: ? */
			info(current.providername, "Vodafone D0x Ix2");
			rsakey = "";
			boxkey = "";
			reader->blockemm = 12;
		}
		// HD+ HD01 RevGC4 (DE) (1830/Sat)
		else if(strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 47 00 44 4E 41 53 50 31 34 32 20 52 65 76 47 43 34 63", 80) == 0 ||
				 // HD+ HD01 RevGC6 (DE) (1830/Sat)
				 strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 47 00 44 4E 41 53 50 31 34 32 20 52 65 76 47 43 36 61", 80) == 0)
		{
			info(current.providername, "Astra HD+ HD01");
			rsakey = "";
			boxkey = "";
			reader->blockemm = 12;
		}
		else if(strncmp(current.atr, "3F FF 95 00 FF 91 81 71 A0 47 00 44 4E 41 53 50 31 38 30 20 4D 65 72 30 30 30 28", 80) == 0)
		{
			// HD+ HD02 (DE) (1843/Sat)
			info(current.providername, "Astra HD+ HD02");
			caid = "1843";
			ident = "1843:000000,003411,008011";
			auprovid = "003411";
			ecmwhitelist = "89";
			ecmheaderwhitelist = "803086078400,813086078400";
			rsakey = "";
			boxkey = "";
			reader->blockemm = 12;
		}
#endif
#ifdef READER_NAGRA_MERLIN
#ifdef READER_NAGRA
		else
#endif
			// HD+ HD03 (DE) (1860/Sat)
			if(strncmp(current.atr, "3F FF 95 00 FF 91 81 71 A0 47 00 44 4E 41 53 50 31 39 30 20 4D 65 72 51 32 35 4F", 80) == 0 ||
				// HD03a (DE) (1860/Sat)
				strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 57 00 44 4E 41 53 50 34 31 30 20 52 65 76 51 32 35 17", 80) == 0 ||
				// HD03b (DE) (1860/Sat)
				strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 57 00 44 4E 41 53 50 34 32 30 20 52 65 76 51 32 35 17", 80) == 0 ||
				// HD04a|b (DE) (186A/Sat)
				strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 57 00 44 4E 41 53 50 34 32 30 20 52 65 76 53 36 30 17", 80) == 0 ||
				// HD04h (DE) (186A/Sat)
				strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 57 00 44 4E 41 53 50 34 32 30 20 52 65 76 53 36 34 13", 80) == 0 ||
				// HD05 (DE) (186A/Sat)
				strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 57 00 44 4E 41 53 50 34 35 30 20 52 65 76 57 36 30 14", 80) == 0)
		{

			info(current.providername, "Astra HD+ HD03/HD04/HD05");

			switch (current.atr[73])
			{
			case 0x32:
				caid = "1860";
				ident = "1860:000000,003411,008011";
				ecmwhitelist = "8F";
				break;
			default: // 0x36
				caid = "186A";
				ident = "186A:000000,003411,008011";
				ecmwhitelist = "8F";
				break;
			}
			auprovid = "003411";
			mod1 = "";
			data50 = "";
			mod50 = "";
			key60 = "";								
			exp60 = "";
			nuid = "";
			cwekey = "";
			reader->nagra_read = 2;
			reader->detect_seca_nagra_tunneled_card = 0;
			reader->cachemm = 1;
			reader->rewritemm = 1;
			reader->logemm = 2;
			reader->deviceemm = 0;
			reader->blockemm = 8;
		}
		else if(strncmp(current.atr, "3F FF 95 00 FF 91 81 71 FE 57 00 44 4E 41 53 50 34 38 32 20 52 65 76 52 32 36 1C", 80) == 0)
		{
			// MAXTV (HR) (1830/Sat)
			info(current.providername, "Max TV");
			reader->blockemm = 8;
		}
#endif
#if defined(READER_NAGRA) && !defined(READER_NAGRA_MERLIN)
		info(current.info, "NAGRA_MERLIN not built in!");
#else
#if !defined(READER_NAGRA)
	info(current.info, "NAGRA not built in!");
#endif
#endif
		break;
	case 0x09:
#ifdef READER_VIDEOGUARD
	{
		int i;
		char buf[66];
		for(i = 10; i < 17; i++)
		{
			// Check for Sky 19.2 E Sat
			snprintf(buf, 66, "3F FF %i 25 03 10 80 41 B0 07 69 FF 4A 50 70 00 00 50 31 01 00 %i", i, i);
			if(strncmp(current.atr, buf, 65) == 0)
			{
				info(current.providername, "Sky Deutschland V13");
				caid = "09C4";
				ident = "09C4:000000";
				ecmheaderwhitelist = "807098000001,817098000001,807060000001,817060000001,80709D000001,81709D000001,80704E000001,81704E000001,807066000001,817066000001,8070B0000001,8170B0000001,8070B3000001,8170B3000001, 8070AF000001, 8170AF000001";
				reader->disablecrccws = 1;
				disablecrccws_only_for = "09C4:000000";
				reader->cachemm = 1;
				reader->rewritemm = 1;
				reader->logemm = 2;
				reader->deviceemm = 0;
				boxid = "";
				ins7E = "";
				k1_generic = "8";
				reader->blockemm = 15;
			}
			snprintf(buf, 63, "3F FD %i 25 02 50 80 0F 41 B0 0A 69 FF 4A 50 F0 00 00 50 31 03", i);
			if(strncmp(current.atr, buf, 62) == 0)
			{
				info(current.providername, "Sky Deutschland V14");
				caid = "098C";
				ident = "098C:000000";
				ecmwhitelist = "56,97,98,A0,9A,9C,9D";
				ecmheaderwhitelist = "81709800000120,80709800000120,8170950000011D,8070950000011D,8070940000011C,8170940000011C,8170540000011D,8070540000011D,8070940000011C94,8170940000011C94,80709A0000011D94,81709A0000011D94";
				reader->disablecrccws = 1;
				disablecrccws_only_for = "098C:000000";
				reader->cachemm = 1;
				reader->rewritemm = 1;
				reader->logemm = 2;
				reader->deviceemm = 0;
				boxid = "";
				ins7E = "";
				k1_generic = "";
				reader->blockemm = 15;
			}
			snprintf(buf, 63, "3F FD %i 25 02 50 80 0F 55 B0 02 69 FF 4A 50 F0 80 00 50 31 03", i);
			if(strncmp(current.atr, buf, 62) == 0)
			{
				info(current.providername, "Sky Deutschland V15");
				caid = "098D";
				ident = "098D:000000";
				reader->disablecrccws = 1;
				disablecrccws_only_for = "098D:000000";
				reader->cachemm = 1;
				reader->rewritemm = 1;
				reader->logemm = 2;
				reader->deviceemm = 0;
				reader->ndsversion = 2;
				boxid = "";
				ins7E = "";
				k1_generic = "";
				reader->blockemm = 15;
			}
			snprintf(buf, 66, "3F FF %i 25 03 10 80 54 B0 01 69 FF 4A 50 70 00 00 4B 57 01 00 00", i);
			if(strncmp(current.atr, buf, 65) == 0)
			{
				info(current.providername, "Sky/Unitymedia V23");
				boxid = "12345678";
				reader->blockemm = 12;
			}
			snprintf(buf, 63, "3F FD %i 25 02 50 00 03 33 B0 15 69 FF 4A 50 F0 80 03 4B 4C 03", i);
			if(strncmp(current.atr, buf, 62) == 0)
			{
				info(current.providername, "Vodafone G09");
				boxid = "12345678";
				reader->blockemm = 12;
				reader->deprecated = 1;
			}
		}
	}
#else
	info(current.info, "VIDEOGUARD not built in!");
#endif
	break;
	}
#if defined(READER_SECA) || defined(READER_VIACCESS) || defined(READER_IRDETO) || defined(READER_CRYPTOWORKS) || defined(READER_NAGRA) || defined(READER_VIDEOGUARD) || defined(READER_NAGRA_MERLIN)
	if(cs_strlen(current.providername))
	{
		int32_t len, s = 0, v = 0;
		info(current.info, "recognized");
		// Reader general settings
		if(!reader->grp)
			reader->grp = 0x1ULL; // cs_log("0x%" PRIx64 "\n",reader->grp);

		if(reader->cardlist >= 2)
		{
			if(caid)
				chk_caidtab(strdup(caid), &reader->ctab);
			if(ident)
				chk_ftab(strdup(ident), &reader->ftab);
			if(auprovid)
				reader->auprovid = a2i(auprovid, 3);
		}
		if(reader->cardlist >= 3 && ecmwhitelist)
		{
			if(ecmwhitelist)
				chk_ecm_whitelist(strdup(ecmwhitelist), &reader->ecm_whitelist);
			if(ecmheaderwhitelist)
				chk_ecm_hdr_whitelist(strdup(ecmheaderwhitelist), &reader->ecm_hdr_whitelist);
		}
		if(disablecrccws_only_for)
			chk_ftab(strdup(disablecrccws_only_for), &reader->disablecrccws_only_for);
		if(rsakey)
		{
			len = cs_strlen(rsakey);
			if(len == 128 || len == 240)
			{
				if(!key_atob_l(rsakey, reader->rsa_mod, len))
					reader->rsa_mod_length = len / 2;
			}
			else
				s++;
		}
		if(deskey)
		{
			len = cs_strlen(deskey);
			if(((len % 16) == 0) && len && len <= 128 * 2)
			{
				if(!key_atob_l(deskey, reader->des_key, len))
					reader->des_key_length = len / 2;
			}
		}
		if(boxkey)
		{
			len = cs_strlen(boxkey);
			if(((len % 8) == 0) && len && len <= 64)
			{
				if(!key_atob_l(boxkey, reader->boxkey, len))
					reader->boxkey_length = len / 2;
			}
			else
				s++;
		}
		if(pincode)
			memcpy(reader->pincode, strdup(pincode), 4);
		if(aeskeys)
		{
			parse_aes_keys(reader, strdup(aeskeys));
		}
		if(s)
		{
			if(reader->caid >> 8 == 0x06)
				info(current.info, "- no keys built in, use config values boxkey + rsakey or disable force_irdeto");
			else
				info(current.info, "- no keys built in, use config values boxkey + rsakey");
		}
#ifdef READER_NAGRA_MERLIN
		int32_t n = 0;
		if(mod1)
		{
			len = cs_strlen(mod1);
			if(len == 224)
			{
				if(!key_atob_l(mod1, reader->mod1, len))
					reader->mod1_length = len / 2;
			}
			else
				n++;
		}
		if(data50)
		{
			len = cs_strlen(data50);
			if(len == 160)
			{
				if(!key_atob_l(data50, reader->data50, len))
					reader->data50_length = len / 2;
			}
			else
				n++;
		}
		if(mod50)
		{
			len = cs_strlen(mod50);
			if(len == 160)
			{
				if(!key_atob_l(mod50, reader->mod50, len))
					reader->mod50_length = len / 2;
			}
			else
				n++;
		}
		if(key60)
		{
			len = cs_strlen(key60);
			if(len == 192)
			{
				if(!key_atob_l(key60, reader->key60, len))
					reader->key60_length = len / 2;
			}
			else
				n++;
		}
		if(exp60)
		{
			len = cs_strlen(exp60);
			if(len == 192)
			{
				if(!key_atob_l(exp60, reader->exp60, len))
					reader->exp60_length = len / 2;
			}
			else
				n++;
		}
		if(nuid)
		{
			len = cs_strlen(nuid);
			if(len == 8)
			{
				if(!key_atob_l(nuid, reader->nuid, len))
					reader->nuid_length = len / 2;
			}
			else
				n++;
		}
		if(cwekey)
		{
			len = cs_strlen(cwekey);
			if(len == 32)
			{
				if(!key_atob_l(cwekey, reader->cwekey, len))
					reader->cwekey_length = len / 2;
			}
			else
				n++;
		}
		if(n)
			info(current.info, "- no keys built in, use config values mod1 + data50 + mod50 + key60+ exp60 + nuid + cwekey");
#endif
		// Reader specific settings for Videoguard
		if(boxid)
			reader->boxid = cs_strlen(boxid) ? a2i(boxid, 4) : 0;
		if(ins7E11)
			fn(ins7E11, reader->ins7E11, 0x01);
		if(ins2e06)
			fn(ins2e06, reader->ins2e06, 0x04);
		if(ins7E)
		{
			if(cs_strlen(ins7E) == 0x1A * 2)
				fn(ins7E, reader->ins7E, 0x1A);
			else
				v++;
		}
		if(k1_generic)
		{
			len = cs_strlen(k1_generic);
			if(len == 16 || len == 32)
			{
				if(!key_atob_l(k1_generic, reader->k1_generic, len))
					reader->k1_generic[16] = len / 2;
			}
			else
				v++;
		}
		if(k1_unique)
		{
			len = cs_strlen(k1_unique);
			if(len == 16 || len == 32)
			{
				if(!key_atob_l(k1_unique, reader->k1_unique, len))
					reader->k1_unique[16] = len / 2;
			}
			else
				v++;
		}
		if(v)
			info(current.info, "- no keys built in, use config values boxid + ins7e + k1_generic + k1_unique");
	}
#endif
	return;
}
#endif // WITH_CARDLIST
