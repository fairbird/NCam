/* FFdecsa -- fast decsa algorithm
 *
 * Copyright (C) 2007 Dark Avenger
 *               2003-2004  fatih89r
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

#include <immintrin.h>

#if __GNUC__ > 10
#define __XOREQ_8_BY__
#endif

/* GROUP */
typedef __m512i group;
static const group ff0 = { 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL };
static const group ff1 = { 0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL };

#define GROUP_PARALLELISM 512
#define FF0() ff0
#define FF1() ff1
#define FFAND(a,b) _mm512_and_si512((a),(b))
#define FFOR(a,b)  _mm512_or_si512((a),(b))
#define FFXOR(a,b) _mm512_xor_si512((a),(b))
#define FFNOT(a)   _mm512_andnot_si512((a),FF1())
#define MALLOC(X)  _mm_malloc(X,64)
#define FREE(X)    _mm_free(X)

/* BATCH */
typedef __m512i batch;
static const batch ff29 = { 0x2929292929292929ULL, 0x2929292929292929ULL, 0x2929292929292929ULL, 0x2929292929292929ULL, 0x2929292929292929ULL, 0x2929292929292929ULL, 0x2929292929292929ULL, 0x2929292929292929ULL };
static const batch ff02 = { 0x0202020202020202ULL, 0x0202020202020202ULL, 0x0202020202020202ULL, 0x0202020202020202ULL, 0x0202020202020202ULL, 0x0202020202020202ULL, 0x0202020202020202ULL, 0x0202020202020202ULL };
static const batch ff04 = { 0x0404040404040404ULL, 0x0404040404040404ULL, 0x0404040404040404ULL, 0x0404040404040404ULL, 0x0404040404040404ULL, 0x0404040404040404ULL, 0x0404040404040404ULL, 0x0404040404040404ULL };
static const batch ff10 = { 0x1010101010101010ULL, 0x1010101010101010ULL, 0x1010101010101010ULL, 0x1010101010101010ULL, 0x1010101010101010ULL, 0x1010101010101010ULL, 0x1010101010101010ULL, 0x1010101010101010ULL };
static const batch ff40 = { 0x4040404040404040ULL, 0x4040404040404040ULL, 0x4040404040404040ULL, 0x4040404040404040ULL, 0x4040404040404040ULL, 0x4040404040404040ULL, 0x4040404040404040ULL, 0x4040404040404040ULL };
static const batch ff80 = { 0x8080808080808080ULL, 0x8080808080808080ULL, 0x8080808080808080ULL, 0x8080808080808080ULL, 0x8080808080808080ULL, 0x8080808080808080ULL, 0x8080808080808080ULL, 0x8080808080808080ULL };

#define BYTES_PER_BATCH 64
#define B_FFN_ALL_29() ff29
#define B_FFN_ALL_02() ff02
#define B_FFN_ALL_04() ff04
#define B_FFN_ALL_10() ff10
#define B_FFN_ALL_40() ff40
#define B_FFN_ALL_80() ff80

#define B_FFAND(a,b) FFAND(a,b)
#define B_FFOR(a,b)  FFOR(a,b)
#define B_FFXOR(a,b) FFXOR(a,b)
#define B_FFSH8L(a,n) _mm512_slli_epi64((a),(n))
#define B_FFSH8R(a,n) _mm512_srli_epi64((a),(n))

#define MEMALIGN_VAL 64
#define M_EMPTY()    _mm_empty()

#undef XOR_8_BY
#define XOR_8_BY(d,s1,s2)    *(__m64*)(d)=_mm_xor_si64(*(__m64*)(s1),*(__m64*)(s2))

#undef XOREQ_8_BY
#define XOREQ_8_BY(d,s)      XOR_8_BY(d,d,s)

#undef COPY_8_BY
#define COPY_8_BY(d,s)       *(__m64*)(d)=*(__m64*)(s)

#undef BEST_SPAN
#define BEST_SPAN            64

#undef XOR_BEST_BY
#define XOR_BEST_BY(d,s1,s2) _mm512_store_si512((group*)(d),_mm512_xor_si512(_mm512_load_si512((group*)(s1)),_mm512_load_si512((group*)(s2))))

#undef XOREQ_BEST_BY
#define XOREQ_BEST_BY(d,s)   XOR_BEST_BY(d,d,s)

inline static void FFTABLEIN(unsigned char *tab, int g, unsigned char *data) { *(((__m64*)tab)+g)=*((__m64*)data); }
inline static void FFTABLEOUT(unsigned char *data, unsigned char *tab, int g) { *((__m64*)data)=*(((__m64*)tab)+g); }
inline static void FFTABLEOUTXORNBY(int n, unsigned char *data, unsigned char *tab, int g)
{
  int j;
  for(j=0;j<n;j++) { *(data+j)^=*(tab+8*g+j); }
}
