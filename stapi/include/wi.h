#if !defined( __WI_SUPPORT_H__ )
#define __WI_SUPPORT_H__
///////////////////////////////////////
//    SOCKET_ID -1, 0, 1, 2, ... ?
//    /mnt/ramdisk/socket_%d.O2W
// /mnt/ramdisk/oscam_socket.O2W = old
///////////////////////////////////////
#ifndef WI_OLD
#ifndef SOCKET_ID
#define SOCKET_ID -1
#endif

typedef unsigned char   u_int8;
typedef unsigned short  u_int16;
typedef unsigned int    u_int32;
#endif

void WiDemux_Init(void);
#ifdef WI_OLD
uint32_t WiDumpMemory(uint8_t *filt, int i, int c);
#else
void WiWrapper_Init(int socket_id);
#endif
uint32_t WiDemux_FilterStart(int32_t demux_id, uint16_t pids, int i, uint8_t *filt, uint8_t *mask, int section, int continues, uint32_t queue, int callback, int timeout, int crc32Check);
uint32_t WiDemux_FilterStop(uint32_t filt);
uint32_t WiDemux_DescramblerKeyExt(int dmxid_ch, uint16_t *pids, int32_t count, uint8_t *cw, int typ);

#endif
