/*
        ifd_amsmc.c
        This module provides IFD handling functions for Amlogic SMC internal reader.
*/

#include "../globals.h"

#ifdef CARDREADER_INTERNAL_AMSMC

#include <linux/types.h>

#include "atr.h"
#include "io_serial.h"

#define AMSMC_MAX_ATR_LEN    33

struct am_smc_atr
{
	unsigned char atr[AMSMC_MAX_ATR_LEN];
	int atr_len;
};

#define AMSMC_IOC_MAGIC 'C'
#define AMSMC_IOC_RESET _IOR(AMSMC_IOC_MAGIC, 0x00, struct am_smc_atr)
#define AMSMC_IOC_GET_STATUS _IOR(AMSMC_IOC_MAGIC, 0x01, int)

#define OK    0
#define ERROR 1

static int32_t Amsmc_GetStatus(struct s_reader *reader, int32_t *status)
{
	call(ioctl(reader->handle, AMSMC_IOC_GET_STATUS, status) < 0);
	return OK;
}

static int32_t Amsmc_Activate(struct s_reader *reader, ATR *atr)
{
	struct am_smc_atr smc_atr;
	if(ioctl(reader->handle, AMSMC_IOC_RESET, &smc_atr) < 0)
	{
		rdr_log(reader, "Error: %s ioctl(AMSMC_IOC_RESET) failed. (%d:%s)", __func__, errno, strerror(errno));
		return ERROR;
	}
	if(ATR_InitFromArray(atr, smc_atr.atr, smc_atr.atr_len) == ERROR)
	{
		rdr_log(reader, "WARNING: ATR is invalid!");
		return ERROR;
	}
	return OK;
}

static int32_t Amsmc_Init(struct s_reader *reader)
{
	const int flags = O_RDWR | O_NOCTTY;
	reader->handle = open(reader->device, flags);
	if(reader->handle < 0)
	{
		rdr_log(reader, "ERROR: Opening device %s (errno=%d %s)", reader->device, errno, strerror(errno));
		return ERROR;
	}
	return OK;
}

static int32_t Amsmc_Close(struct s_reader *reader)
{
	rdr_log_dbg(reader, D_DEVICE, "Closing AMSMC device %s", reader->device);
	if(reader->handle >= 0)
	{
		if(close(reader->handle) != 0)
		{
			return ERROR;
		}
		reader->handle = -1;
	}
	return OK;
}

const struct s_cardreader cardreader_internal_amsmc =
{
	.desc            = "internal",
	.typ             = R_INTERNAL,
	.flush           = 1,
	.max_clock_speed = 1,
	.reader_init     = Amsmc_Init,
	.get_status      = Amsmc_GetStatus,
	.activate        = Amsmc_Activate,
	.transmit        = IO_Serial_Transmit,
	.receive         = IO_Serial_Receive,
	.close           = Amsmc_Close,
};

#endif
