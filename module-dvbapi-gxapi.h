#ifndef _MODULE_GXAPI_H_
#define _MODULE_GXAPI_H_

typedef struct
{
	unsigned int DemuxID;
	unsigned int FilterNum;
	unsigned int DemuxNum;
	unsigned short Pid;
	unsigned char Depth;
	unsigned char FilterData[16];
	unsigned char FilterMask[16];
	void *pParams;
	int (*pFilterCallback)(void *pParams, unsigned char *pSecData, unsigned int SecLen);

	int SoftFilter;
	unsigned char SoftFilterDepth;
	unsigned char SoftFilterData[16];
	unsigned char SoftFilterMask[16];
} gxapi_filter_open;

#define DESC_MAX_NUM 16 // Maximum number of descramblers

typedef struct
{
	unsigned int DemuxID;
	unsigned short Pid;
	unsigned int Idx;
} gxapi_desc_open;

extern int gxdvbapi_init(void);
extern int gxapi_open_filter(gxapi_filter_open *pOpenParams, unsigned int *pFilterHandle);
extern int gxapi_close_filter(unsigned int FilterHandle);
extern int gxapi_get_slotid_by_pid(unsigned short pid, int demux_idx);

extern int gxapi_open_desc(gxapi_desc_open *pOpenParams, unsigned int *pDescHandle);
extern int gxapi_close_desc(unsigned int DescHandle);
extern int gxapi_set_desc(int demux_id, unsigned short StreamPid, unsigned char *pOddCW, unsigned char *pEvenCW);
extern int gxapi_get_desc_handle(int demux_id, unsigned short StreamPid, unsigned int *handle_p);
extern int gxapi_set_desc_by_handle(unsigned int DescHandle, unsigned char *pOddCW, unsigned char *pEvenCW);

#endif
