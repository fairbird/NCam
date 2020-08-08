#ifndef __GXAPI_H__
#define __GXAPI_H__

/*****************************const define*************************************/

typedef enum gxav_channel_type
{
	GXAV_NO_PTS_FIFO   = (1 << 0),
	GXAV_PTS_FIFO      = (1 << 1),
	GXAV_WPROTECT_FIFO = (1 << 2),
	GXAV_RPROTECT_FIFO = (1 << 3),
} GxAvChannelType;

typedef enum _PinFlag
{
	GX_PINFLAG_NO_PTS_FIFO = GXAV_NO_PTS_FIFO,
	GX_PINFLAG_PTS_FIFO = GXAV_PTS_FIFO,
	GX_PINFLAG_WPROTECT_FIFO = GXAV_WPROTECT_FIFO,
	GX_PINFLAG_SW,
	GX_PINFLAG_MUXTS,
	GX_PINFLAG_MUXER,
	GX_PINFLAG_ESV  = (1 << 16) | GXAV_PTS_FIFO,
	GX_PINFLAG_WKV  = (1 << 17) | GXAV_NO_PTS_FIFO,
	GX_PINFLAG_FBV  = (1 << 18) | GXAV_NO_PTS_FIFO,
	GX_PINFLAG_ESA  = (1 << 19) | GXAV_PTS_FIFO,
	GX_PINFLAG_ESA1 = (1 << 20) | GXAV_PTS_FIFO,
	GX_PINFLAG_WKA  = (1 << 21) | GXAV_NO_PTS_FIFO,
	GX_PINFLAG_PCM  = (1 << 22) | GXAV_NO_PTS_FIFO,
	GX_PINFLAG_PCM1 = (1 << 23) | GXAV_NO_PTS_FIFO,
	GX_PINFLAG_AC3  = (1 << 24) | GXAV_NO_PTS_FIFO,
	GX_PINFLAG_EAC3 = (1 << 25) | GXAV_NO_PTS_FIFO,
	GX_PINFLAG_TSR  = (1 << 26) | GXAV_NO_PTS_FIFO | GXAV_WPROTECT_FIFO,
	GX_PINFLAG_TSW  = (1 << 27) | GXAV_NO_PTS_FIFO,
	GX_PINFLAG_DTS  = (1 << 28) | GXAV_NO_PTS_FIFO,
	GX_PINFLAG_MASK = 0xffff0000
} GxPinFlag;

/*****************************struct define*************************************/

#define DEMUX_FILTER_MAX_LEN 16

typedef struct
{
	int                  demux_idx;                        // Hardware demux
	unsigned int         SectionSize;                      // Maximum section length
	unsigned short       Pid;
	unsigned char        FilterData[DEMUX_FILTER_MAX_LEN];
	unsigned char        FilterMask[DEMUX_FILTER_MAX_LEN];
	int                  AutoStop;                         // Whether to stop automatically, now useless
	void                 *AuxParam_p;                      // Extra parameters, when the data is received and the following callback is called, the parameter is returned
	void                 (*Callback_p)(int SectionHandle, void *AuxParam_p, unsigned char *SectionData_p, unsigned short SectionLen);

	int                  DirectCallback;                   // Call callback directly

	// Patch for the core platform
	int                  SoftFilter;
	unsigned char        SoftFilterData[DEMUX_FILTER_MAX_LEN];
	unsigned char        SoftFilterMask[DEMUX_FILTER_MAX_LEN];
} filteropen_t; // Open section

typedef struct
{
	/*Valid key bit
	(PAL_DEMUX_DESCRAMBLER_KEY_ODD) Odd effective/
	(PAL_DEMUX_DESCRAMBLER_KEY_EVEN) Even effective/
	(PAL_DEMUX_DESCRAMBLER_KEY_ODD | PAL_DEMUX_DESCRAMBLER_KEY_EVEN) Parity effective*/
	unsigned char        KeyMask;
	unsigned char        OddKey[8];                        // Odd key
	unsigned char        EvenKey[8];                       // Even key
} descramblerset_t; // De-scrambling data

typedef struct
{
	int                  demux_idx;                        // Corresponding hardware demultiplexing name
	unsigned short       Pid;                              // Corresponding stream PID
} descrambleropen_t; // Open descrambler

/*****************************gloal data define**********************************/

// Choose the first few sci controllers, some chips support 2 sci
typedef enum
{
	__GXSMART_SCI1 = 0,
	__GXSMART_SCI2
} GxSmcSelect;

// Smart Card Communication Resend Protocol
typedef enum
{
	ENABLE_REPEAT_WHEN_ERR, // Resend one byte when checking for errors, so that each interaction will send an additional acknowledge bit (T0)
	DISABLE_REPEAT_WHEN_ERR // It is not resent when checking for errors. It is generally recommended to use this mode (T1)
} GxSmcRepeat_t;

// Smart card VCC level
typedef enum
{
	GXSMC_VCC_HIGH_LEVEL,
	GXSMC_VCC_LOW_LEVEL
} GxSmcVccPol;

// Whether to use the hardware to recognize the ETU during reset. If yes, after reset,
// you need to get the ETU value according to the response and then configure it.
typedef enum
{
	GXSMC_RESET_VIA_SET_ETU,
	GXSMC_RESET_VIA_AUTO_ETU,
} GxSmcAutoEtu_t;

// Smart card communication stop bit
typedef enum
{
	GXSMC_STOPLEN_0BIT,
	GXSMC_STOPLEN_1BIT,
	GXSMC_STOPLEN_1D5BIT,
	GXSMC_STOPLEN_2BIT
} GxSmcStopLen;

// Smart card trigger level
typedef enum
{
	GXSMC_DETECT_LOW_LEVEL       = 0,
	GXSMC_DETECT_HIGH_LEVEL      = 1
} GxSmcDetectPol;

// Smart card communication data reversal
typedef enum
{
	GXSMC_DATA_CONV_DIRECT       = 0,
	GXSMC_DATA_CONV_INVERSE      = 1
} GxSmcDataConv;

// Smart card communication check
typedef enum
{
	GXSMC_PARITY_ODD             = 0,
	GXSMC_PARITY_EVEN            = 1
} GxSmcParityType;

// Smart card status
typedef enum
{
	GXSMC_CARD_INIT              = 0,
	GXSMC_CARD_IN                = 1,
	GXSMC_CARD_OUT               = 2
} GxSmcCardStatus;

// Smart card interface communication time parameter
typedef enum
{
	SMCT_NONE,
	SMCT_FRE   = 0X00000001,
	SMCT_ETU   = 0X00000002,
	SMCT_EGT   = 0X00000004,
	SMCT_TGT   = 0X00000008,
	SMCT_WDT   = 0X00000010,
	SMCT_TWDT  = 0X00000020,
	SMCT_ALL   = 0X0000003F
} GxSmcTimeConfigFlags;

typedef struct
{
	GxSmcTimeConfigFlags flags;
	uint32_t             baud_rate;                        // Smart card frequency, such as 9600 * 372
	uint32_t             etu;
	uint32_t             egt;
	uint32_t             tgt;
	uint32_t             wdt;
	uint32_t             twdt;
} GxSmcTimeParams;

typedef enum
{
	SMCC_NONE,
	SMCC_PROTOCOL                 = 0X00000001,
	SMCC_STOPLEN                  = 0X00000002,
	SMCC_DATACONV                 = 0X00000004,
	SMCC_PARITYTYPE               = 0X00000008,
	SMCC_TIME                     = 0X00000010,
	SMCC_AUTO_ENABLE              = 0X00000100,
	SMCC_AUTO_ETU_ENABLE          = 0X00000200,
	SMCC_AUTO_CONV_PARITY_ENABLE  = 0X00000400,
	SMCC_AUTO_DISABLE             = 0X00001000,
	SMCC_AUTO_ETU_DISABLE         = 0X00002000,
	SMCC_AUTO_CONV_PARITY_DISABLE = 0X00004000,
	SMCC_ALL                      = 0X0000001F

} GxSmcConfigFlags;

typedef struct
{
	GxSmcConfigFlags     flags;
	GxSmcRepeat_t        protocol;
	GxSmcStopLen         stop_len;
	GxSmcDataConv        io_conv;
	GxSmcParityType      parity;
	GxSmcTimeParams      time;
} GxSmcConfigs;

typedef struct
{
#define O_BDBG (1)                                         // Open bus debugging information
#define O_CDBG (1 << 1)                                    // Turn on driver debugging information

	GxSmcRepeat_t        protocol;
	GxSmcStopLen         stop_len;
	GxSmcDataConv        io_conv;
	GxSmcParityType      parity;
	GxSmcVccPol          vcc_pole;
	GxSmcDetectPol       detect_pole;
	GxSmcSelect          sci_sel;
	GxSmcAutoEtu_t       auto_etu;                         // 1, auto
	uint32_t             auto_parity;                      // 1, auto
	uint32_t             default_etu;                      // Default etu value
	uint32_t             debug_info;
} GxSmcParams;

/*****************************function define*******************************/

#if defined(HAVE_DVBAPI) && defined(WITH_GXAPI)
extern int oscam_gxapi_init(void);
extern int oscam_gxapi_close(void);
extern int oscam_gxapi_open_filter(filteropen_t *OpenParam_p, unsigned int *Handle_p);
extern int oscam_gxapi_close_filter(int Handle);
extern int oscam_gxapi_flush_filter(int Handle);
extern int oscam_gxapi_get_slotid_by_pid(unsigned short pid, int demux_idx);
extern int oscam_gxapi_open_descrambler(descrambleropen_t *OpenParam_p, int *Handle_p);
extern int oscam_gxapi_close_descrambler(int Handle);
extern int oscam_gxapi_set_descrambler(int Handle, descramblerset_t *DescramblerData_p);

extern int oscam_gxapi_open_smc(const char *name, GxSmcParams *param);
extern int oscam_gxapi_reset(int handle, uint8_t *AtrBuf, size_t BufSize, size_t *RetLen);
extern int oscam_gxapi_configure(int handle, const GxSmcTimeParams *time);
extern int oscam_gxapi_configure_all(int handle, const GxSmcConfigs *config);
extern int oscam_gxapi_send_cmd(int handle, const uint8_t *Cmd, size_t CmdLen);
extern int oscam_gxapi_get_reply_entend(int handle, uint8_t *ReplyBuf, size_t BufSize, size_t timeout);
extern int oscam_gxapi_get_reply(int handle, uint8_t *ReplyBuf, size_t BufSize);
extern int oscam_gxapi_get_status (int handle, GxSmcCardStatus *state);
extern int oscam_gxapi_close_smc(int handle);
#endif

#endif
