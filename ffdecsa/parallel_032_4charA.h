/* FFdecsa -- fast decsa algorithm
 *
 * Copyright (C) 2003-2004  fatih89r
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */


struct group_t{
  unsigned char s1[4];
};
typedef struct group_t group;

#define GROUP_PARALLELISM 32

inline static group FF0(){
  group res;
  int i;
  for(i=0;i<4;i++) res.s1[i]=0x0;
  return res;
}

inline static group FF1(){
  group res;
  int i;
  for(i=0;i<4;i++) res.s1[i]=0xff;
  return res;
}

inline static group FFAND(group a,group b){
  group res;
  int i;
  for(i=0;i<4;i++) res.s1[i]=a.s1[i]&b.s1[i];
  return res;
}

inline static group FFOR(group a,group b){
  group res;
  int i;
  for(i=0;i<4;i++) res.s1[i]=a.s1[i]|b.s1[i];
  return res;
}

inline static group FFXOR(group a,group b){
  group res;
  int i;
  for(i=0;i<4;i++) res.s1[i]=a.s1[i]^b.s1[i];
  return res;
}

inline static group FFNOT(group a){
  group res;
  int i;
  for(i=0;i<4;i++) res.s1[i]=~a.s1[i];
  return res;
}


/* 64 rows of 32 bits */

inline static void FFTABLEIN(unsigned char *tab, int g, unsigned char *data){
  *(((int *)tab)+g)=*((int *)data);
  *(((int *)tab)+32+g)=*(((int *)data)+1);
}

inline static void FFTABLEOUT(unsigned char *data, unsigned char *tab, int g){
  *((int *)data)=*(((int *)tab)+g);
  *(((int *)data)+1)=*(((int *)tab)+32+g);
}

inline static void FFTABLEOUTXORNBY(int n, unsigned char *data, unsigned char *tab, int g){
  int j;
  for(j=0;j<n;j++){
    *(data+j)^=*(tab+4*(g+(j>=4?32-1:0))+j);
  }
}

struct batch_t{
  unsigned char s1[4];
};
typedef struct batch_t batch;

#define BYTES_PER_BATCH 4

inline static batch B_FFAND(batch a,batch b){
  batch res;
  int i;
  for(i=0;i<4;i++) res.s1[i]=a.s1[i]&b.s1[i];
  return res;
}

inline static batch B_FFOR(batch a,batch b){
  batch res;
  int i;
  for(i=0;i<4;i++) res.s1[i]=a.s1[i]|b.s1[i];
  return res;
}

inline static batch B_FFXOR(batch a,batch b){
  batch res;
  int i;
  for(i=0;i<4;i++) res.s1[i]=a.s1[i]^b.s1[i];
  return res;
}


inline static batch B_FFN_ALL_29(){
  batch res;
  int i;
  for(i=0;i<4;i++) res.s1[i]=0x29;
  return res;
}
inline static batch B_FFN_ALL_02(){
  batch res;
  int i;
  for(i=0;i<4;i++) res.s1[i]=0x02;
  return res;
}
inline static batch B_FFN_ALL_04(){
  batch res;
  int i;
  for(i=0;i<4;i++) res.s1[i]=0x04;
  return res;
}
inline static batch B_FFN_ALL_10(){
  batch res;
  int i;
  for(i=0;i<4;i++) res.s1[i]=0x10;
  return res;
}
inline static batch B_FFN_ALL_40(){
  batch res;
  int i;
  for(i=0;i<4;i++) res.s1[i]=0x40;
  return res;
}
inline static batch B_FFN_ALL_80(){
  batch res;
  int i;
  for(i=0;i<4;i++) res.s1[i]=0x80;
  return res;
}

inline static batch B_FFSH8L(batch a,int n){
  batch res;
  int i;
  for(i=0;i<4;i++) res.s1[i]=a.s1[i]<<n;
  return res;
}

inline static batch B_FFSH8R(batch a,int n){
  batch res;
  int i;
  for(i=0;i<4;i++) res.s1[i]=a.s1[i]>>n;
  return res;
}

inline static void M_EMPTY(void){
}
