/* Copyright (C) 2012,2013,2014 EnergySec
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Scott Weston <scott.david.weston@gmail.com>
 *
 * Definitions and macros for IEC 61131-3 data types.
 *
 */

#if !defined(_icsiec61131_h)
#define _icsiec61131_h

typedef uint8_t			iecBOOL;
typedef char			iecSINT;
typedef int16_t			iecINT;
typedef int32_t			iecDINT;
typedef int64_t			iecLINT;
typedef uint8_t			iecUSINT;
typedef uint16_t		iecUINT;
typedef uint32_t		iecUDINT;
typedef uint64_t		iecULINT;
typedef float			iecREAL;
typedef double			iecLREAL;
typedef iecINT			iecITIME;
typedef iecDINT			iecTIME;
typedef iecDINT			iecFTIME;
typedef iecLINT			iecLTIME;
typedef iecINT			iecDATE;
typedef iecREAL			iecTIMEOFDAY;
typedef iecREAL			iecDATAANDTIME;
typedef iecSINT			iecSTRING;
typedef iecINT			iecSTRING2;
typedef iecINT			iecSTRING3;
typedef struct {
	iecUSINT length;
	iecSINT  *string;
} 						iecSHORTSTRING;
typedef iecSTRING2		iecSTRINGI;
typedef uint8_t			iecBYTE;
typedef uint16_t		iecWORD;
typedef uint32_t		iecDWORD;
typedef uint64_t		iecLWORD;
typedef struct {
	iecUSINT length;
	iecUSINT type;
	iecBOOL  padded;
	iecBYTE  *data;
} 						iecEPATH;
typedef iecUINT			iecENGUNIT;

#define iecTRUE			((iecBOOL) 1)
#define iecFALSE		((iecBOOL) 0)

#define ICS_BOOL(b) {										\
	if(octets - o < 1) 										\
		return ICS_RESULT_SHORT;							\
	b = *(data + o);										\
	o += 1;
#define ICS_BYTE(b)											\
	if(octets - o < 1) 										\
		return ICS_RESULT_SHORT;							\
	b = *(data + o);										\
	o += 1;
#define ICS_BYTES(bs, n)									\
	if(octets - o < n) 										\
		return ICS_RESULT_SHORT;							\
	bs = (iecBYTE *) icsMalloc(n + 1);						\
	if(bs == NULL)											\
		return ICS_RESULT_OUTOFMEMORY;						\
	ICS_MEMTRACEADD(bs, iecBYTE, n + 1);					\
	memcpy(bs, data + o, n);								\
	o += n;
#define ICS_WORD(w)											\
	if(octets - o < 2) 										\
		return ICS_RESULT_SHORT;							\
	w = *((iecWORD *) (data + o));							\
	o += 2;
#define ICS_WORDS(ws, n)									\
	if(octets - o < n * 2)		 							\
		return ICS_RESULT_SHORT;							\
	ws = (iecWORD *) icsMalloc((n + 1) * 2);				\
	if(ws == NULL)											\
		return ICS_RESULT_OUTOFMEMORY;						\
	ICS_MEMTRACEADD(ws, iecWORD, (n + 1) * 2);				\
	memcpy(ws, data + o, n*2);								\
	o += n * 2;
#define ICS_DWORD(dw)										\
	if(octets - o < 4) 										\
		return ICS_RESULT_SHORT;							\
	dw = *((iecDWORD *) (data + o));						\
	o += 4;
#define ICS_DWORDS(dws, n) 									\
	if(octets - o < n * 4)		 							\
		return ICS_RESULT_SHORT;							\
	dws = (iecDWORD *) icsMalloc((n + 1) * 4);				\
	if(dws == NULL)											\
		return ICS_RESULT_OUTOFMEMORY;						\
	ICS_MEMTRACEADD(dws, iecDWORD, (n + 1) * 4);			\
	memcpy(dws, data + o, n * 4);							\
	o += n * 2;
#define ICS_LWORD(lw) {										\
	if(octets - o < 8) 										\
		return ICS_RESULT_SHORT;							\
	lw = *((iecLWORD *) (data + o));						\
	o += 8;													\
}
#define ICS_LWORDS(lws, n) 									\
	if(octets - o < n * 8)		 							\
		return ICS_RESULT_SHORT;							\
	lws = (iecLWORD *) icsMalloc((n + 1) * 8);				\
	if(dws == NULL)											\
		return ICS_RESULT_OUTOFMEMORY;						\
	ICS_MEMTRACEADD(lws, iecLWORD, (n + 1) * 8);			\
	memcpy(lws, data + o, n * 8);							\
	o += n * 8;
#define ICS_SINT(si)										\
	if(octets - o < 1) 										\
		return ICS_RESULT_SHORT;							\
	si = (iecSINT) *(data + o);								\
	o += 1;
#define ICS_SINTS(sis, n) 									\
	if(octets - o < n) 										\
		return ICS_RESULT_SHORT;							\
	sis = (iecSINT *) icsMalloc(n + 1);						\
	if(sis == NULL)											\
		return ICS_RESULT_OUTOFMEMORY;						\
	ICS_MEMTRACEADD(sis, iecSINT, n + 1);					\
	memcpy(sis, data + o, n);								\
	o += n;
#define ICS_INT(i) 											\
	if(octets - o < 2) 										\
		return ICS_RESULT_SHORT;							\
	i = *((iecINT *) (data + o));							\
	o += 2;
#define ICS_INTS(is, n)										\
	if(octets - o < n * 2) 									\
		return ICS_RESULT_SHORT;							\
	is = (iecINT *) icsMalloc((n + 1) * 2);					\
	if(is == NULL)											\
		return ICS_RESULT_OUTOFMEMORY;						\
	ICS_MEMTRACEADD(is, iecINT, (n + 1) * 2);				\
	{	int i;												\
		for(i=0; i < n; i++) {								\
			is[i] = *((iecINT *) (data + o));				\
			o += 2;											\
		}													\
	}
#define ICS_DINT(di) 										\
	if(octets - o < 4) 										\
		return ICS_RESULT_SHORT;							\
	di = *((iecDINT *) (data + o));							\
	o += 4;
#define ICS_DINTS(dis, n) 									\
	if(octets - o < n * 4) 									\
		return ICS_RESULT_SHORT;							\
	dis = (iecDINT *) icsMalloc((n + 1) * 4);				\
	if(dis == NULL)											\
		return ICS_RESULT_OUTOFMEMORY;						\
	ICS_MEMTRACEADD(dis, iecDINT, (n + 1) * 4);				\
	{	int i;												\
		for(i=0; i < n; i++) {								\
			dis[i] = *((iecDINT *) (data + o));				\
			o += 4;											\
		}													\
	}
#define ICS_LINT(li)										\
	if(octets - o < 8) 										\
		return ICS_RESULT_SHORT;							\
	li = *((iecLINT *) (data + o));							\
	o += 8;
#define ICS_LINTS(lis, n)									\
	if(octets - o < n * 8) 									\
		return ICS_RESULT_SHORT;							\
	lis = (iecLINT *) icsMalloc((n + 1) * 8);				\
	if(lis == NULL)											\
		return ICS_RESULT_OUTOFMEMORY;						\
	ICS_MEMTRACEADD(lis, iecLINT, (n + 1) * 8);				\
	{	int i;												\
		for(i=0; i < n; i++) {								\
			lis[i] = *((iecLINT *) (data + o));				\
			o += 8;											\
		}													\
	}
#define ICS_USINT(usi) 										\
	if(octets - o < 1) 										\
		return ICS_RESULT_SHORT;							\
	usi = (iecUSINT) *(data + o);							\
	o += 1;
#define ICS_USINTS(usis, n) 								\
	if(octets - o < n) 										\
		return ICS_RESULT_SHORT;							\
	usis = (iecUSINT *) icsMalloc(n + 1);					\
	if(usis == NULL)										\
		return ICS_RESULT_OUTOFMEMORY;						\
	ICS_MEMTRACEADD(usis, iecUSINT, n + 1);					\
	memcpy(usis, data + o, n);								\
	o += n;
#define ICS_UINT(ui) 										\
	if(octets - o < 2) 										\
		return ICS_RESULT_SHORT;							\
	ui = *((iecUINT *) (data + o));							\
	o += 2;
#define ICS_UINTS(uis, n) 									\
	if(octets - o < n * 2) 									\
		return ICS_RESULT_SHORT;							\
	uis = (iecUINT *) icsMalloc((n + 1) * 2);				\
	if(uis == NULL)											\
		return ICS_RESULT_OUTOFMEMORY;						\
	ICS_MEMTRACEADD(uis, iecUINT, (n + 1) * 2);				\
	{	int i;												\
		for(i=0; i < n; i++) {								\
			uis[i] = *((iecUINT *) (data + o));				\
			o += 2;											\
		}													\
	}
#define ICS_UDINT(udi) 										\
	if(octets - o < 4) 										\
		return ICS_RESULT_SHORT;							\
	udi = *((iecUDINT *) (data + o));						\
	o += 4;
#define ICS_UDINTS(udis, n) 								\
	if(octets - o < n * 4) 									\
		return ICS_RESULT_SHORT;							\
	udis = (iecUDINT *) icsMalloc((n + 1) * 4);				\
	if(udis == NULL)										\
		return ICS_RESULT_OUTOFMEMORY;						\
	ICS_MEMTRACEADD(udis, iecUDINT, (n + 1) * 4);			\
	{ 	int i;												\
		for(i=0; i < n; i++) {								\
			udis[i] = *((iecUDINT *) (data + o));			\
			o += 4;											\
		}													\
	}
#define ICS_ULINT(uli) 										\
	if(octets - o < 8) 										\
		return ICS_RESULT_SHORT;							\
	uli = *((iecULINT *) (data + o));						\
	o += 8;
#define ICS_ULINTS(ulis, n) 								\
	if(octets - o < n * 8) 									\
		return ICS_RESULT_SHORT;							\
	ulis = (iecULINT *) icsMalloc((n + 1) * 8);				\
	if(ulis == NULL)										\
		return ICS_RESULT_OUTOFMEMORY;						\
	ICS_MEMTRACEADD(ulis, iecULINT, (n + 1) * 8);			\
	{	int i;												\
		for(i=0; i < n; i++) {								\
			ulis[i] = *((iecULINT *) (data + o));			\
			o += 8;											\
		}													\
	}
#define ICS_REAL(r) 										\
	if(octets - o < 4) 										\
		return ICS_RESULT_SHORT;							\
	iecUDINT t = *((iecUDINT *) (data + o));				\
	r = *((iecREAL *) &t);									\
	o += 4;
#define ICS_REALS(rs, n) 									\
	if(octets - o < n * 4) 									\
		return ICS_RESULT_SHORT;							\
	rs = (iecREAL *) icsMalloc((n + 1) * 4);				\
	if(rs == NULL)											\
		return ICS_RESULT_OUTOFMEMORY;						\
	ICS_MEMTRACEADD(rs, iecREAL, (n + 1) * 4);				\
	{	int i;												\
		for(i=0; i < n; i++) {								\
			iecUDINT t = *((iecUDINT *) (data + o));		\
			rs[i] = *((iecREAL *) &t);						\
			o += 4;											\
		}													\
	}
#define ICS_LREAL(lr) 										\
	if(octets - o < 8) 										\
		return ICS_RESULT_SHORT;							\
	iecULINT uli;											\
	uli.value[1] = *((iecUDINT *) (data + o));				\
	o += 2;													\
	uli.value[0] = *((iecUDINT *) (data + o));				\
	o += 2;													\
	lr = *((iecLREAL *) &uli);
#define ICS_LREALS(lrs, n) 									\
	if(octets - o < n * 8) 									\
		return ICS_RESULT_SHORT;							\
	lrs = (iecLREAL *) icsMalloc((n + 1) * 8);				\
	if(lrs == NULL)											\
		return ICS_RESULT_OUTOFMEMORY;						\
	ICS_MEMTRACEADD(lrs, iecLREAL, (n + 1) * 8);			\
	{	int i;												\
		for(i=0; i < n; i++) {								\
			iecULINT uli;									\
			uli.value[1] = *((iecUDINT *) (data + o));		\
			o += 4;											\
			uli.value[0] = *((iecUDINT *) (data + o));		\
			o += 4;											\
			lrs[i] = *((iecLREAL *) &uli);					\
		}													\
	}
#define ICS_STRING3(s3, n) 									\
	s3 = icsMalloc((n + 1) * 4);							\
	if(s3 == NULL)											\
		return ICS_RESULT_OUTOFMEMORY;						\
	ICS_MEMTRACEADD(s3, iecSTRING3, (n + 1) * 4);			\
	{	int i;												\
		iecBYTE triple[4];									\
		void *tptr = triple;								\
		for(i=0; i < n; i++) {								\
			triple[3] = '\0';								\
			triple[2] = *(data + o++);						\
			triple[1] = *(data + o++);						\
			triple[0] = *(data + o++);						\
			s3[i] = *((iecINT *) tptr);						\
		}													\
	}
#define ICS_SHORTSTRING(ss) 								\
	ss = icsMalloc(sizeof(iecSHORTSTRING));					\
	if(ss == NULL)											\
		return ICS_RESULT_OUTOFMEMORY;						\
	ICS_MEMTRACEADD(ss, iecSHORTSTRING, 					\
			sizeof(iecSHORTSTRING));						\
	ICS_USINT(ss->length);									\
	ICS_SINTS(ss->string, ss->length);

#define ICS_ITIME(it)				ICS_INT(it)
#define ICS_ITIMES(its, n)			ICS_INTS(its, n)
#define ICS_TIME(t)					ICS_INT(it)
#define ICS_TIMES(ts)				ICS_INTS(ts, n)
#define ICS_FTIME(ft)				ICS_DINT(ft)
#define ICS_FTIMES(fts, n)			ICS_DINTS(fts, n)
#define ICS_LTIME(lt)				ICS_LINT(lt)
#define ICS_LTIMES(lts, n)			ICS_LINTS(lts, n)
#define ICS_DATE(d)					ICS_INT(d)
#define ICS_DATES(ds, n)			ICS_INTS(ds, n)
#define ICS_TIMEOFDAY(tod)			ICS_REAL(tod)
#define ICS_TIMEOFDAYS(tods, n)		ICS_REALS(tods, n)
#define ICS_DATEANDTIME(dat)		ICS_REAL(dat)
#define ICS_DATEANDTIMES(dats, n)	ICS_REALS(dats, n)
#define ICS_STRING(s1, n)			ICS_SINTS(s1, n)
#define ICS_STRING2(s2, n)			ICS_INTS(s2, n)
#define ICS_STRINGI(si, n)			ICS_STRING2(si, n)

#define ICS_INT_BE(i) 										\
	if(octets - o < 2) 										\
		return ICS_RESULT_SHORT;							\
	i = htons(*((iecINT *) (data + o)));					\
	o += 2;
#define ICS_INTS_BE(is, n)									\
	if(octets - o < n * 2) 									\
		return ICS_RESULT_SHORT;							\
	is = (iecINT *) icsMalloc((n + 1) * 2);					\
	if(is == NULL)											\
		return ICS_RESULT_OUTOFMEMORY;						\
	{	int i;												\
		for(i=0; i < n; i++) {								\
			is[i] = htons(*((iecINT *) (data + o)));		\
			o += 2;											\
		}													\
	}
#define ICS_DINT_BE(di)										\
	if(octets - o < 4) 										\
		return ICS_RESULT_SHORT;							\
	di = htonl(*((iecDINT *) (data + o)));					\
	o += 4;
#define ICS_DINTS_BE(dis, n) 								\
	if(octets - o < n * 4) 									\
		return ICS_RESULT_SHORT;							\
	dis = (iecDINT *) icsMalloc((n + 1) * 4);				\
	if(dis == NULL)											\
		return ICS_RESULT_OUTOFMEMORY;						\
	{	int i;												\
		for(i=0; i < n; i++) {								\
			dis[i] = htonl(*((iecDINT *) (data + o)));		\
			o += 4;											\
		}													\
	}
#define ICS_UINT_BE(ui)										\
	if(octets - o < 2) 										\
		return ICS_RESULT_SHORT;							\
	ui = htons(*((iecUINT *) (data + o)));					\
	o += 2;
#define ICS_UINTS_BE(uis, n) 								\
	if(octets - o < n * 2) 									\
		return ICS_RESULT_SHORT;							\
	uis = (iecUINT *) icsMalloc((n + 1) * 2);				\
	if(uis == NULL)											\
		return ICS_RESULT_OUTOFMEMORY;						\
	{	int i;												\
		for(i=0; i < n; i++) {								\
			uis[i] = htons(*((iecUINT *) (data + o)));		\
			o += 2;											\
		}													\
	}														\
}
#define ICS_UDINT_BE(udi) 									\
	if(octets - o < 4) 										\
		return ICS_RESULT_SHORT;							\
	udi = htonl(*((iecUDINT *) (data + o)));				\
	o += 4;
#define ICS_UDINTS_BE(udis, n) 								\
	if(octets - o < n * 4) 									\
		return ICS_RESULT_SHORT;							\
	udis = (iecUDINT *) icsMalloc((n + 1) * 4);				\
	if(udis == NULL)										\
		return ICS_RESULT_OUTOFMEMORY;						\
	{ 	int i;												\
		for(i=0; i < n; i++) {								\
			udis[i] = htonl(*((iecUDINT *) (data + o)));	\
			o += 4;											\
		}													\
	}
#define ICS_REAL_BE(r) 										\
	if(octets - o < 4) 										\
		return ICS_RESULT_SHORT;							\
	iecUDINT t = htonl(*((iecUDINT *) (data + o)));			\
	r = *((iecREAL *) &t);									\
	o += 4;
#define ICS_REALS_BE(rs, n) 								\
	if(octets - o < n * 4) 									\
		return ICS_RESULT_SHORT;							\
	rs = (iecREAL *) icsMalloc((n + 1) * 4);				\
	if(rs == NULL)											\
		return ICS_RESULT_OUTOFMEMORY;						\
	{	int i;												\
		for(i=0; i < n; i++) {								\
			iecUDINT t = 									\
				htonl(*((iecUDINT *) (data + o)));			\
			rs[i] = *((iecREAL *) &t);						\
			o += 4;											\
		}													\
	}
#define ICS_LREAL_BE(lr) 									\
	if(octets - o < 8) 										\
		return ICS_RESULT_SHORT;							\
	iecULINT uli;											\
	uli.value[1] = htonl(*((iecUDINT *) (data + o)));		\
	o += 2;													\
	uli.value[0] = htonl(*((iecUDINT *) (data + o)));		\
	o += 2;													\
	lr = *((iecLREAL *) &uli);
#define ICS_LREALS_BE(lrs, n) 								\
	if(octets - o < n * 8) 									\
		return ICS_RESULT_SHORT;							\
	lrs = (iecLREAL *) icsMalloc((n + 1) * 8);				\
	if(lrs == NULL)											\
		return ICS_RESULT_OUTOFMEMORY;						\
	{	int i;												\
		for(i=0; i < n; i++) {								\
			iecULINT uli;									\
			uli.value[1] = 									\
				htonl(*((iecUDINT *) (data + o)));			\
			o += 4;											\
			uli.value[0] =	 								\
				htonl(*((iecUDINT *) (data + o)));			\
			o += 4;											\
			lrs[i] = *((iecLREAL *) &uli);					\
		}													\
	}

#define ICS_ITIME_BE(it)				ICS_INT_BE(it)
#define ICS_ITIMES_BE(its, n)			ICS_INTS_BE(its, n)
#define ICS_TIME_BE(t)					ICS_INT_BE(it)
#define ICS_TIMES_BE(ts)				ICS_INTS_BE(ts, n)
#define ICS_FTIME_BE(ft)				ICS_DINT_BE(ft)
#define ICS_FTIMES_BE(fts, n)			ICS_DINTS_BE(fts, n)
#define ICS_DATE_BE(d)					ICS_INT_BE(d)
#define ICS_DATES_BE(ds, n)				ICS_INTS_BE(ds, n)
#define ICS_TIMEOFDAY_BE(tod)			ICS_REAL_BE(tod)
#define ICS_TIMEOFDAYS_BE(tods, n)		ICS_REALS_BE(tods, n)
#define ICS_DATEANDTIME_BE(dat)			ICS_REAL_BE(dat)
#define ICS_DATEANDTIMES_BE(dats, n)	ICS_REALS_BE(dats, n)
#define ICS_STRING2_BE(s2, n)			ICS_UINTS_BE(s2, n)
#define ICS_STRINGI_BE(si, n)			ICS_STRING2_BE(si, n)

#endif
