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
 * Common Primitives.
 *
 */

#if !defined _icscommon_h
#define _icscommon_h

//#include "ics.h"

#define stricmp strcasecmp

iecUDINT *icsNumberArrayFromCommaList(iecSINT *list, iecUDINT def, iecUINT *pu);

iecSINT  *icsBin2Hexdump(iecBYTE *data, iecUDINT octets);
iecUSINT *icsHexdump2Bin(iecSINT *hexdump, iecUDINT *pl);

iecSINT *icsRemoveQuotes(const iecSINT *s);
void icsFreeStringArray(iecSINT **p);

iecSINT *icsStrdup(const iecSINT *s);
iecSINT *icsStrndup(const iecSINT *s, size_t n);

iecUSINT icsGetOctet(const iecUSINT *p, int o);
iecUSINT *icsGetOctets(const iecUSINT *p, int o, int n);

iecUINT icsGetWord(const iecUSINT *p, int o, iecBOOL hostMode);
iecUINT *icsGetWords(const iecUSINT *p, int o, int n, iecBOOL hostMode);

iecUDINT icsGetTriple(const iecUSINT *p, int o, iecBOOL hostMode);
iecUDINT *icsGetTriples(const iecUSINT *p, int o, int n, iecBOOL hostMode);

iecUDINT icsGetDWord(const iecUSINT *p, int o, iecBOOL hostMode);
iecUDINT *icsGetDWords(const iecUSINT *p, int o, int n, iecBOOL hostMode);

iecULINT icsGetQWord(const iecUSINT *p, int o, iecBOOL hostMode);
iecULINT *icsGetQWords(const iecUSINT *p, int o, int n, iecBOOL hostMode);

iecULINT icsGetBits(iecUSINT *p, int o, int l, iecBOOL hostMode);

IcsOpaque *icsGetItem(iecUSINT *p, int o, int l);
IcsOpaque *icsGetItems(iecUSINT *p, int o, int l, int n);

typedef struct tagIcsHashItem {
    iecSINT *k;
    IcsOpaque *v;
    unsigned long h;
    struct tagIcsHashItem *n;
} IcsHashItem;

typedef struct tagIcsHash {
    int a;
    int t;
    unsigned long s;
    unsigned long p;
    unsigned long l;
    unsigned long x;
    unsigned long iu;
    unsigned long ts;
    unsigned long hw;
    IcsHashItem *ii;
    IcsHashItem **items;
} IcsHash;

typedef enum tagIcsHashAlgorithm {
    SCHA_DEFAULT = 0,
    SCHA_DJB2,
    SCHA_SDBM,
    SCHA_ELF
} IcsHashAlgorithm;

int icsHashFree(IcsHash *h);
int icsHashSetItem(IcsHash *h, const iecSINT *key, const IcsOpaque *value);
IcsHash *icsHashCreate(int initialSize, int threshold, IcsHashAlgorithm algorithm);
IcsOpaque *icsHashDeleteItem(IcsHash *h, const iecSINT *key);
IcsOpaque *icsHashFirstItem(IcsHash *h, iecSINT **key);
IcsOpaque *icsHashGetItem(IcsHash *h, const iecSINT *key);
IcsOpaque *icsHashNextItem(IcsHash *h, iecSINT **key);

typedef struct tagIcsFifoItem {
    IcsOpaque *v;
    struct tagIcsFifoItem *p;
    struct tagIcsFifoItem *n;
} IcsFifoItem;

typedef struct tagIcsFifo {
    IcsFifoItem *h;
    IcsFifoItem *t;
} IcsFifo;

IcsFifo *icsFifoCreate(void);
int icsFifoFree(IcsFifo *fifo);
int icsFifoPush(IcsFifo *fifo, IcsOpaque *v);
IcsOpaque *icsFifoPop(IcsFifo *fifo);

typedef struct tagIcsRx {
    IcsOpaque *p;
    IcsOpaque *pe;
    int global;
} IcsRx;

iecSINT **icsRxMatch(const iecSINT *s, const iecSINT *rx);
iecSINT **icsRxSplit(const iecSINT *s, const iecSINT *rx);
iecSINT *icsRxReplace(const iecSINT *s, const iecSINT *r, const iecSINT *rx);
void icsRxFreeCache(void);

typedef struct tagIcsQueueItem {
    size_t sz;
    IcsOpaque *ptr;
    struct tagIcsQueueItem *p, *n;
} IcsQueueItem;

typedef struct tagIcsQueue {
    unsigned long max;
    unsigned long put;
    unsigned long get;
    IcsQueueItem *h;
    IcsQueueItem *t;
} IcsQueue;

int icsQueueAddItem(IcsQueue *q, const IcsOpaque *ptr, size_t sz);
int icsQueueFree(IcsQueue *q);
int icsQueueIsEmpty(IcsQueue *q);
IcsQueue *icsQueueCreate(int max, int ttl);
IcsOpaque *icsQueueGetItem(IcsQueue *q, size_t *psz);

#endif

