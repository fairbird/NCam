#include "../globals.h"
#include "io_serial.h"

#if defined(CARDREADER_GXAPI)
#include "atr.h"
#include "../ncam-string.h"

#include "../extapi/goceed/gxapi.h"

#undef OK
#undef ERROR

#define OK 0
#define ERROR 1

#define IFD_SC_DEBUG
#define IFD_SC_ERROR

//#define GOXCEED_INTERNAL
#define SMC_RECV_ONE_TIME

#ifdef IFD_SC_DEBUG
#ifdef DEBF
#undef DEBF
#endif
#define DEBF(fmt, arg...) cs_log(fmt, ##arg)
#else
#define DEBF(fmt, arg...)
#endif

// Error message:
#ifdef IFD_SC_ERROR
#undef ERRF
#define ERRF(fmt, arg...) cs_log(fmt, ##arg)
#else
#define ERRF(fmt, arg...)
#endif /*OS_ERROR */

#define SMC_DEV_NAME ("/dev/gxsmartcard0")

struct gxapi_data
{
	int32_t smc_handle;
};

#ifdef SMC_RECV_ONE_TIME
#define SMC_RECV_MAX (1024)

static unsigned char Recvbuf[SMC_RECV_MAX];
static unsigned int RecvIndex = 0;
static unsigned int RecvReserved = 0;
#endif

static uint8_t bInit = 0;

static int32_t gxapi_init(struct s_reader *reader)
{
	GxSmcParams param;
	//struct gxapi_data

	if(!cs_malloc(&reader->crdr_data, sizeof(struct gxapi_data)))
	{
		return ERROR;
	}

	struct gxapi_data *crdr_data = reader->crdr_data;

	if(bInit == 0)
	{
		/*for gxceed platform ,we use smc_slot to
		config detect pole temple*/
		memset(&param, 0, sizeof(param));

		param.detect_pole = GXSMC_DETECT_LOW_LEVEL;

		param.io_conv = GXSMC_DATA_CONV_DIRECT;
		param.parity = GXSMC_PARITY_EVEN;
		param.protocol = DISABLE_REPEAT_WHEN_ERR;
		param.sci_sel = __GXSMART_SCI1;
		param.stop_len = GXSMC_STOPLEN_0BIT;
		param.vcc_pole = GXSMC_VCC_HIGH_LEVEL;
		param.default_etu = 372;
		param.auto_etu = 1;
		param.auto_parity = 1;
		//param.debug_info = O_BDBG|O_CDBG;

		crdr_data->smc_handle =  oscam_gxapi_open_smc(SMC_DEV_NAME,&param);
		if(crdr_data->smc_handle <= 0)
		{
			DEBF("Error %s;%d \n",__FUNCTION__,__LINE__);
			return ERROR;
		}

		bInit = 1;
	}

	return OK;
}

static int32_t gxapi_close(struct s_reader *reader)
{
	struct gxapi_data *crdr_data = reader->crdr_data;

	//DEBF("%s;%d \n",__FUNCTION__,__LINE__);
	if(bInit == 0)
	{
		DEBF("Error, Smardcard device is not init, close failed !! \n");
		return ERROR;
	}

	if(crdr_data->smc_handle <= 0)
	{
		DEBF("%s;%d \n", __FUNCTION__, __LINE__);
		return ERROR;

	}

	if(oscam_gxapi_close_smc(crdr_data->smc_handle) < 0)
	{
		DEBF("%s;%d \n", __FUNCTION__, __LINE__);
		return ERROR;
	}

	bInit = 0;
	return OK;
}

static int32_t gxapi_getstatus(struct s_reader *reader, int32_t *in)
{
	int ret;
	GxSmcCardStatus state;
	struct gxapi_data *crdr_data = reader->crdr_data;

	if(crdr_data->smc_handle <= 0)
	{
		DEBF("%s;%d \n", __FUNCTION__, __LINE__);
		return ERROR;
	}

	*in = 0;

	ret = oscam_gxapi_get_status(crdr_data->smc_handle, &state);
	if(ret < 0)
	{
		DEBF("Error:%s !!ret = %d \n",__FUNCTION__,ret);
		return ERROR;
	}

	if(state == GXSMC_CARD_IN)
	{
		*in = 1;
	}

	return OK;
}

static int32_t gxapi_reset(struct s_reader *reader, ATR *atr)
{
	int ret;
	unsigned char atrbuf[256];
	unsigned int retLen;
	struct gxapi_data *crdr_data = reader->crdr_data;

	if(crdr_data->smc_handle <= 0)
	{
		DEBF("%s;%d \n", __FUNCTION__, __LINE__);
		return ERROR;
	}

	ret = oscam_gxapi_reset(crdr_data->smc_handle, atrbuf, 33/*sizeof(atrbuf)*/, &retLen);
	if(ret >= 0)
	{
		DEBF("STB_SC_reset OK!! \n");

		if(ATR_InitFromArray(atr, atrbuf, retLen) == ERROR)
		{
			DEBF("Error:ATR_InitFromArray!\n");
			return ERROR;
		}

		return OK;
	}

	DEBF("Error:STB_SC_reset !!ret = %d \n",ret);
	return ERROR;
}

#ifdef GOXCEED_INTERNAL
static int32_t gxapi_write(struct s_reader *reader, const uchar *buf, unsigned char *cta_res, uint16_t *cta_lr, int32_t l)
{
	int ret;
	uint8_t sw1,sw2;
	struct gxapi_data *crdr_data = reader->crdr_data;

	if(crdr_data->smc_handle <= 0)
	{
		DEBF("Error,%s;%d \n", __FUNCTION__, __LINE__);
		return ERROR;
	}

	ret = GxSmc_SendReceiveData(crdr_data->smc_handle,l, buf, cta_res, cta_lr, &sw1, &sw2);

	if(ret < 0)
	{
		DEBF("Error:%s !!ret = %d \n", __FUNCTION__, ret);
		return ERROR;
	}

#if 0 //#ifdef IFD_SC_DEBUG
{
	int i;


	DEBF("bSW :0x%02X%02X\n",bSW[0],bSW[1]);
	DEBF("u32NumberRead = %d \n",u32NumberRead);
	DEBF("Read Data :0x");
	for(i = 0;i < u32NumberRead;i++)
	{
		DEBF("Read Data :%02X",cta_res[i]);
	}
}
#endif
	cta_res[*cta_lr] = sw1;
	cta_res[*cta_lr + 1] = sw2;
	*cta_lr = *cta_lr + 2;

	return OK;
}
#else
static int32_t gxapi_transmit(struct s_reader *reader, unsigned char *sent, uint32_t size, uint32_t UNUSED(expectedlen),uint32_t UNUSED(delay), uint32_t UNUSED(timeout))
{
	int ret;
	//UINT32 u32NumberWritten = 0;
	struct gxapi_data *crdr_data = reader->crdr_data;

	if(crdr_data->smc_handle <= 0)
	{
		DEBF("Error,%s;%d \n",__FUNCTION__,__LINE__);
		return ERROR;
	}

	ret = oscam_gxapi_send_cmd(crdr_data->smc_handle, sent, size);
	if(ret < 0)
	{
		ERRF("Error:%s !!ret = %d \n",__FUNCTION__,ret);
		return ERROR;
	}

	RecvReserved = 0;

	return OK;
}

static int32_t gxapi_receive(struct s_reader *reader, unsigned char *sent, uint32_t size, uint32_t UNUSED(delay), uint32_t UNUSED(timeout))
{
	int ret;
	//UINT32 u32NumberRead = 0;
	struct gxapi_data *crdr_data = reader->crdr_data;

	if(crdr_data->smc_handle <= 0)
	{
		DEBF("Error,%s;%d \n", __FUNCTION__, __LINE__);
		return ERROR;
	}

#ifdef SMC_RECV_ONE_TIME
	if(RecvReserved != 0 && size > RecvReserved)
	{
		ERRF("Error:%s ,not enough bytes !!\n", __FUNCTION__);
		return ERROR;
	}

	if(RecvReserved == 0)
	{
		ret = oscam_gxapi_get_reply(crdr_data->smc_handle, Recvbuf, SMC_RECV_MAX);
		if(ret < 0)
		{
			ERRF("Error:%s !!ret = %d \n", __FUNCTION__, ret);
			return ERROR;
		}

		RecvReserved = ret;
		RecvIndex = 0;
	}

	memcpy(sent, &Recvbuf[RecvIndex], size);
	RecvIndex += size;
	RecvReserved -= size;
	ret = size;
#else
	ret = oscam_gxapi_get_reply(crdr_data->smc_handle, sent, size);
	if(ret < 0)
	{
		ERRF("Error:%s !!ret = %d \n",__FUNCTION__,ret);
		return ERROR;
	}

#endif
#if 0
	{
		int i;
		cs_log("\n#########################RECEIVE->: ret: %d#############################\n",ret);
		for(i = 0 ; i < ret; i++)
			cs_log("%02x ",sent[i]);
		cs_log("\n#########################RECEIVE:<- ####################################\n");

	}
#endif
	return OK;
}

//static int32_t goxceed_writesettings(struct s_reader *reader, uint32_t ETU, uint32_t EGT, unsigned char P, unsigned char I, uint16_t Fi, unsigned char Di, unsigned char Ni)
#endif

static int32_t gxapi_writesettings(struct s_reader *reader, struct s_cardreader_settings *s)
{
	int ret;
	GxSmcConfigs config;

	memset(&config, 0, sizeof(config));
	//unsigned char conax_atr[] = {0x3B, 0x24, 0x00, 0x30, 0x42, 0x30, 0x30};
	struct gxapi_data *crdr_data = reader->crdr_data;

	if(crdr_data->smc_handle <= 0)
	{
		DEBF("Error,%s;%d \n", __FUNCTION__, __LINE__);
		return ERROR;
	}

	if(reader->convention == ATR_CONVENTION_DIRECT)
	{
		config.io_conv = GXSMC_DATA_CONV_DIRECT;
		config.flags |= SMCC_DATACONV;
	}
	else
	{
		config.io_conv = GXSMC_DATA_CONV_INVERSE;
		config.flags |= SMCC_DATACONV;
	}

	config.flags |= SMCC_TIME;
	config.time.flags = (SMCT_EGT | SMCT_TGT | SMCT_TWDT | SMCT_WDT);

	if(s->ETU)
	{
		config.time.flags |= SMCT_ETU;
		config.time.etu = (float) 372 / ((float) reader->current_baudrate / 9600);
	}
	//use default clock rate now ,irdeto set to hight speed has problem
	//config.time.baud_rate = reader->mhz*10000;
	//cs_log("fun = %s, line = %d (EGT:%d,ETU: %d,WWT: %d, BGT: %d,Fi:%d ,Di:%d,Ni:%d,P:%d,I:%d,F:%d,D: %d)\n",__FUNCTION__,__LINE__,s->EGT,s->ETU,s->WWT,s->BGT,s->Fi,s->Di,s->Ni,s->P,s->I,s->F,s->D);
	config.time.egt = 2 * s->F / s->D;
	config.time.tgt = reader->block_delay * s->F / s->D;
	config.time.twdt = reader->read_timeout * s->F / s->D;
	/*receive start delay*/
	config.time.wdt = 100 * s->F / s->D;
	//configed to auto when open, so just ignore it
	//cs_log("bud = %d, egt = %d,tgt = %d,twdt = %d,wdt = %d,etu = %d\n",config.time.baud_rate,config.time.egt,config.time.tgt,config.time.twdt,config.time.wdt,config.time.etu);
	ret = oscam_gxapi_configure_all(crdr_data->smc_handle, &config);
	if(ret < 0)
	{
		DEBF("%s;%d \n", __FUNCTION__, __LINE__);
		return ERROR;
	}
	return OK;
}

#if 0
static int32_t gxapi_set_baudrate(struct s_reader *reader, unsigned int baudrate)
{
	int ret;
	GxSmcConfigs config = {0};
	struct gxapi_data *crdr_data = reader->crdr_data;

	if(crdr_data->smc_handle <= 0)
	{
		DEBF("%s;%d \n",__FUNCTION__,__LINE__);
		return ERROR;
	}

	config.flags = SMCC_TIME;
	config.time.flags = SMCT_ETU;
	config.time.etu = (float)372/((float)baudrate/9600);
	//DEBF("goxceed_set_baudrate %d \n", config.time.etu);

	ret = oscam_gxapi_configure_all(crdr_data->smc_handle,&config);
	if(ret < 0)
	{
		DEBF("%s;%d \n",__FUNCTION__,__LINE__);
		return ERROR;
	}

	return OK;
}

static int32_t gxapi_setparity (struct s_reader *reader, uchar parity)
{
	int ret;
	GxSmcConfigs config = {0};
	struct gxapi_data *crdr_data = reader->crdr_data;

	if(crdr_data->smc_handle <= 0)
	{
		DEBF("Error,%s;%d \n",__FUNCTION__,__LINE__);
		return ERROR;
	}

	config.flags = SMCC_PARITYTYPE;
	if(parity == PARITY_ODD)
	{
		config.parity = GXSMC_PARITY_ODD;
	}
	else if(parity == PARITY_EVEN)
	{
		config.parity = GXSMC_PARITY_EVEN;
	}
	else
	{
		DEBF("Error,%s;%d \n",__FUNCTION__,__LINE__);
		return ERROR;
	}

	ret = oscam_gxapi_configure_all(crdr_data->smc_handle,&config);
	if(ret < 0)
	{
		DEBF("Error,%s;%d \n",__FUNCTION__,__LINE__);
		return ERROR;
	}

	return OK;

}
#endif

const struct s_cardreader cardreader_gxapi =
{
	.desc           = "internal",
	.typ            = R_INTERNAL,
	.reader_init    = gxapi_init,
	.get_status     = gxapi_getstatus,
	.activate       = gxapi_reset,
	.transmit       = gxapi_transmit,
	.receive        = gxapi_receive,
	.close          = gxapi_close,
	.set_protocol   = NULL,
	.write_settings = gxapi_writesettings,
	.set_baudrate   = NULL,
	.set_parity     = NULL,
};

#endif
