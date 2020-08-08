/* Reversed from libcoolstream.so, this comes without any warranty */
#define MODULE_LOG_PREFIX "dvbgxapi"

#include "globals.h"

#if defined(HAVE_DVBAPI) && defined(WITH_GXAPI)
#include "extapi/goceed/gxapi.h"
#include "module-dvbapi.h"
#include "module-dvbapi-gxapi.h"
#include "ncam-client.h"
#include "ncam-files.h"
#include "ncam-string.h"
#include "ncam-time.h"

//#ifndef TRUE
#define TRUE (1)
//#endif

//#ifndef FALSE
#define FALSE (0)
//#endif

extern void *dvbapi_client;

typedef struct
{
	unsigned char bOpen;
	unsigned int hChannel;
	unsigned int hFilter;
	void *pParams;

	unsigned int hDemuxidx;
	unsigned int hFilternum;
	unsigned int hDemuxnum;

	int (*pFilterCallback)(void *pParams, unsigned char *pSecData, unsigned int SecLen);
} gxapi_filter_t;

#define MAX_FILTER_NUM 48

static pthread_mutex_t filter_lock;
static gxapi_filter_t Filter[MAX_FILTER_NUM];

typedef struct
{
	int Valid;
	int ReferCnt;
	int DemuxId;
	unsigned int Idx;
	unsigned short Pid;
	unsigned char OddKey[8];
	unsigned char EvenKey[8];
	int DesHandle;

} gxapi_desc_t;

static pthread_mutex_t desc_lock;
gxapi_desc_t DescInst[DESC_MAX_NUM];

static void FilterSectionCallback(int SectionHandle, void *UNUSED(AuxParam_p), unsigned char *SectionData_p, unsigned short SectionLen)
{
	int i, seclen;
	unsigned int demux_id, filter_num;
	unsigned char *p = SectionData_p;
	unsigned char *p_data = NULL;
	gxapi_filter_t *pFilter = NULL;

	SAFE_SETSPECIFIC(getclient, dvbapi_client);
	//cs_log_dump_dbg(D_DVBAPI, SectionData_p, SectionLen, "FilterSectionCallback:");

	SAFE_MUTEX_LOCK(&filter_lock);
	for(i = 0; i < MAX_FILTER_NUM; i++)
	{
		if(Filter[i].bOpen && (Filter[i].hFilter == (unsigned int)SectionHandle))
		{
			pFilter = &Filter[i];
			break;
		}
	}

	if(pFilter == NULL)
	{
		cs_log("ERROR: %s, %d", __FUNCTION__, __LINE__);
		SAFE_MUTEX_UNLOCK(&filter_lock);

		return;
	}

	seclen = (((p[1] << 8) | p[2]) & 0x0FFF) + 3;
	if(seclen > SectionLen)
	{
		cs_log("ERROR: %s, %d", __FUNCTION__, __LINE__);
		SAFE_MUTEX_UNLOCK(&filter_lock);

		return;
	}

	demux_id = pFilter->hDemuxnum;
	filter_num = pFilter->hFilternum;

	if(cs_malloc(&p_data, seclen))
	{
		memcpy(p_data,p,seclen);
	}
	SAFE_MUTEX_UNLOCK(&filter_lock);

	if(p_data)
	{
		dvbapi_process_input(demux_id, filter_num, p_data, seclen, 0);
		NULLFREE(p_data);
	}

	return;
}

int gxdvbapi_init(void)
{
	cs_log("%s, %d", __FUNCTION__, __LINE__);

	memset(Filter, 0, sizeof(Filter));
	memset(DescInst, 0, sizeof(DescInst));

	SAFE_MUTEX_INIT(&filter_lock, NULL);
	SAFE_MUTEX_INIT(&desc_lock, NULL);

	oscam_gxapi_init();

	return 0;
}

int gxapi_open_filter(gxapi_filter_open *pOpenParams, unsigned int *pFilterHandle)
{
	int i, ret;
	gxapi_filter_t *pFilter = NULL;
	filteropen_t SectionParam;
	unsigned int Handle;

	if(pOpenParams == NULL || pFilterHandle == NULL)
	{
		cs_log("ERROR: %s, %d", __FUNCTION__, __LINE__);
		return -1;
	}

#if 0
	if(pOpenParams->pFilterCallback == NULL)
	{
		cs_log("ERROR: %s, %d", __FUNCTION__, __LINE__);
		return -1;
	}
#endif

	SAFE_MUTEX_LOCK(&filter_lock);
	for(i = 0; i < MAX_FILTER_NUM; i++)
	{
		if(!Filter[i].bOpen)
		{
			pFilter = &Filter[i];
			break;
		}
	}

	if(pFilter == NULL)
	{
		cs_log("ERROR: %s, %d", __FUNCTION__, __LINE__);
		SAFE_MUTEX_UNLOCK(&filter_lock);

		return -1;
	}

	memset(&SectionParam, 0, sizeof(SectionParam));

	memset(SectionParam.FilterData, 0, sizeof(SectionParam.FilterData));
	memset(SectionParam.FilterMask, 0, sizeof(SectionParam.FilterMask));
	memcpy(SectionParam.FilterData, pOpenParams->FilterData, pOpenParams->Depth);
	memcpy(SectionParam.FilterMask, pOpenParams->FilterMask, pOpenParams->Depth);
	SectionParam.SectionSize = 1024;
	SectionParam.Pid = pOpenParams->Pid;
	SectionParam.demux_idx = pOpenParams->DemuxID;
	SectionParam.AutoStop = FALSE;
	SectionParam.Callback_p = FilterSectionCallback;
	SectionParam.AuxParam_p = (void *)(SectionParam.demux_idx);

	//SectionParam.SoftFilter = pOpenParams->SoftFilter;
	//memcpy(SectionParam.SoftFilterData, pOpenParams->SoftFilterData, pOpenParams->SoftFilterDepth);
	//memcpy(SectionParam.SoftFilterMask, pOpenParams->SoftFilterMask, pOpenParams->SoftFilterDepth);

	ret = oscam_gxapi_open_filter(&SectionParam, &Handle);
	if(ret != 0)
	{
		cs_log("ERROR: %s, %d", __FUNCTION__, __LINE__);
		SAFE_MUTEX_UNLOCK(&filter_lock);

		return -1;
	}

	pFilter->bOpen = TRUE;
	pFilter->hFilter = Handle;
	pFilter->pParams = pOpenParams->pParams;
	pFilter->hDemuxidx = pOpenParams->DemuxID;
	pFilter->hFilternum = pOpenParams->FilterNum;
	pFilter->hDemuxnum = pOpenParams->DemuxNum;
	pFilter->pFilterCallback = pOpenParams->pFilterCallback;
	*pFilterHandle = (unsigned int)pFilter;
	SAFE_MUTEX_UNLOCK(&filter_lock);

	//cs_log("%s; FilterHandle = 0x%X", __FUNCTION__, *pFilterHandle);

	return 0;
}

int gxapi_get_slotid_by_pid(unsigned short pid, int demux_idx)
{
	return oscam_gxapi_get_slotid_by_pid(pid, demux_idx);
}

int gxapi_close_filter(unsigned int FilterHandle)
{
	int ret;

	//cs_log("%s IN; FilterHandle = 0x%X", __FUNCTION__, FilterHandle);

	gxapi_filter_t *pFilter = (gxapi_filter_t *)FilterHandle;

	if(pFilter == NULL)
	{
		cs_log("ERROR: %s, %d", __FUNCTION__, __LINE__);
		return -1;
	}

	SAFE_MUTEX_LOCK(&filter_lock);
	if(!pFilter->bOpen)
	{
		cs_log("ERROR: %s, %d", __FUNCTION__, __LINE__);
		SAFE_MUTEX_UNLOCK(&filter_lock);

		return -1;
	}

	ret = oscam_gxapi_close_filter(pFilter->hFilter);
	if(ret != 0)
	{
		cs_log("ERROR: %s, %d", __FUNCTION__, __LINE__);
		SAFE_MUTEX_UNLOCK(&filter_lock);

		return -1;

	}

	memset(pFilter, 0, sizeof(gxapi_filter_t));
	SAFE_MUTEX_UNLOCK(&filter_lock);

	//cs_log("%s OUT; FilterHandle = 0x%X", __FUNCTION__, FilterHandle);

	return 0;
}

static int DCW_NULL(const unsigned char *dcw)
{
	int i;

	for(i = 0; i < 8; i++)
	{
		if(dcw[i])
		{
			return 0;
		}
	}

	return 1;
}

int gxapi_open_desc(gxapi_desc_open *pOpenParams, unsigned int *pDescHandle)
{
	int i, ret;
	gxapi_desc_t *Inst_p = NULL;
	descrambleropen_t OpenParam;

	//cs_log("Demuxid = %d, Pid = %d", pOpenParams->DemuxID, pOpenParams->Pid);

	if(pDescHandle == NULL || pOpenParams == NULL)
	{
		return -1;
	}

	SAFE_MUTEX_LOCK(&desc_lock);
#if 1
	for(i = 0; i < DESC_MAX_NUM; i++)
	{
		Inst_p = &(DescInst[i]);

		if((Inst_p->Valid == TRUE) && ((unsigned int)Inst_p->DemuxId == pOpenParams->DemuxID)
			&& (Inst_p->Pid == pOpenParams->Pid))
		{
			*pDescHandle = i;
			SAFE_MUTEX_UNLOCK(&desc_lock);

			return 0;
		}
	}
#endif

	for(i = 0; i < DESC_MAX_NUM; i++)
	{
		if(DescInst[i].Valid == FALSE)
		{
			break;
		}
	}

	if(i >= DESC_MAX_NUM)
	{
		SAFE_MUTEX_UNLOCK(&desc_lock);

		return -1;
	}

	Inst_p = &(DescInst[i]);
	OpenParam.demux_idx = pOpenParams->DemuxID;
	OpenParam.Pid = pOpenParams->Pid;

	ret = oscam_gxapi_open_descrambler(&OpenParam, &Inst_p->DesHandle);
	if(ret != 0)
	{
		SAFE_MUTEX_UNLOCK(&desc_lock);

		return -1;
	}

	Inst_p->DemuxId = pOpenParams->DemuxID;
	Inst_p->Pid = pOpenParams->Pid;
	Inst_p->Idx = pOpenParams->Idx;

	Inst_p->Valid = TRUE;
	Inst_p->ReferCnt = 0;
	*pDescHandle = i;

	SAFE_MUTEX_UNLOCK(&desc_lock);

	return 0;
}

int gxapi_close_desc(unsigned int DescHandle)
{
	int ret;
	gxapi_desc_t *Inst_p = NULL;

again:
	SAFE_MUTEX_LOCK(&desc_lock);
	if(DescHandle >= DESC_MAX_NUM)
	{
		SAFE_MUTEX_UNLOCK(&desc_lock);

		return -1;
	}

	Inst_p = &(DescInst[DescHandle]);

	if(Inst_p->ReferCnt)
	{
		SAFE_MUTEX_UNLOCK(&desc_lock);

		cs_sleepms(100);
		goto again;
	}

	if(Inst_p->Valid == FALSE)
	{
		cs_log("Error, descrambler already closed");
		SAFE_MUTEX_UNLOCK(&desc_lock);

		return -1;
	}

	ret = oscam_gxapi_close_descrambler(Inst_p->DesHandle);
	if(ret != 0)
	{
		SAFE_MUTEX_UNLOCK(&desc_lock);

		return -1;
	}

	Inst_p->Valid = FALSE;
	SAFE_MUTEX_UNLOCK(&desc_lock);

	return 0;
}

int gxapi_set_desc(int demux_id, unsigned short StreamPid, unsigned char *pOddCW, unsigned char *pEvenCW)
{
	int i, ret;
	gxapi_desc_t *Inst_p = NULL;

	//cs_log("stream pid = %d, demux_id = %d",StreamPid, demux_id);

	//cs_log("ODD:%02x %02x %02x %02x %02x %02x %02x %02x",
	//	pOddCW[0], pOddCW[1], pOddCW[2], pOddCW[3], pOddCW[4], pOddCW[5], pOddCW[6], pOddCW[7]);
	//cs_log("EVEN:%02x %02x %02x %02x %02x %02x %02x %02x",
	//	pEvenCW[0], pEvenCW[1], pEvenCW[2], pEvenCW[3], pEvenCW[4], pEvenCW[5], pEvenCW[6], pEvenCW[7]);

	if(DCW_NULL(pOddCW) && DCW_NULL(pEvenCW))
	{
		return -1;
	}

	// Don't fix CW chekcsum bytes
	//pEvenCW[3] = (pEvenCW[0] + pEvenCW[1] + pEvenCW[2]) & 0xFF;
	//pEvenCW[7] = (pEvenCW[4] + pEvenCW[5] + pEvenCW[6]) & 0xFF;
	//pOddCW[3] = (pOddCW[0] + pOddCW[1] + pOddCW[2]) & 0xFF;
	//pOddCW[7] = (pOddCW[4] + pOddCW[5] + pOddCW[6]) & 0xFF;

	SAFE_MUTEX_LOCK(&desc_lock);
	for(i = 0; i < DESC_MAX_NUM; i++)
	{
		Inst_p = &(DescInst[i]);

		if((Inst_p->Valid == TRUE) && (Inst_p->DemuxId == demux_id)
			&& ((Inst_p->Pid == StreamPid) || (8192 == StreamPid)))
		{
			descramblerset_t DescramblerData;

			memcpy(DescramblerData.EvenKey, pEvenCW, 8);
			memcpy(DescramblerData.OddKey, pOddCW, 8);
			memcpy(Inst_p->EvenKey, pEvenCW, 8);
			memcpy(Inst_p->OddKey, pOddCW, 8);

			ret = oscam_gxapi_set_descrambler(Inst_p->DesHandle, &DescramblerData);
			if(ret != 0)
			{
				//cs_log("error, set cw!!");
			}
		}
	}
	SAFE_MUTEX_UNLOCK(&desc_lock);

	return 0;
}

int gxapi_get_desc_handle(int demux_id, unsigned short StreamPid, unsigned int *handle_p)
{
	int i;
	gxapi_desc_t *Inst_p = NULL;

	SAFE_MUTEX_LOCK(&desc_lock);
	for(i = 0; i < DESC_MAX_NUM; i++)
	{
		Inst_p = &(DescInst[i]);

		if((Inst_p->Valid == TRUE) && (Inst_p->DemuxId == demux_id) && Inst_p->Pid == StreamPid)
		{
			*handle_p = i;
			break;
		}
	}
	SAFE_MUTEX_UNLOCK(&desc_lock);

	return i == DESC_MAX_NUM ? -1 : 0;
}

int gxapi_set_desc_by_handle(unsigned int DescHandle, unsigned char *pOddCW, unsigned char *pEvenCW)
{
	int ret;
	gxapi_desc_t *Inst_p = NULL;
	descramblerset_t DescramblerData;

	SAFE_MUTEX_LOCK(&desc_lock);
	if(DescHandle >= DESC_MAX_NUM)
	{
		SAFE_MUTEX_UNLOCK(&desc_lock);

		return -1;
	}

	Inst_p = &(DescInst[DescHandle]);

	if(Inst_p->Valid == FALSE)
	{
		SAFE_MUTEX_UNLOCK(&desc_lock);

		return -1;
	}

	memcpy(Inst_p->EvenKey, pEvenCW, 8);
	memcpy(Inst_p->OddKey, pOddCW, 8);

	memcpy(DescramblerData.EvenKey, Inst_p->EvenKey, 8);
	memcpy(DescramblerData.OddKey, Inst_p->OddKey, 8);

	ret = oscam_gxapi_set_descrambler(Inst_p->DesHandle, &DescramblerData);
	if(ret != 0)
	{
		cs_log("error, set cw!!");
		SAFE_MUTEX_UNLOCK(&desc_lock);

		return -1;
	}
	SAFE_MUTEX_UNLOCK(&desc_lock);

	return 0;
}

#if 1
#undef cs_log
void cs_log(const char *fmt, ...)
{
	va_list params;
	char log_txt[512];

	va_start(params, fmt);
	vsnprintf(log_txt, sizeof(log_txt), fmt, params);
	va_end(params);

	//printf("%s",log_txt);
	cs_log_txt(MODULE_LOG_PREFIX, "%s", log_txt);
}
#endif

#endif
