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
 * Common primitives.
 *
 */

#include "ics.h"
#include "icscommon.h"

#include <pcre.h>

iecUDINT *icsNumberArrayFromCommaList(iecSINT *list, iecUDINT def, iecUINT *pu)
{
    char defitem[128];
    snprintf(defitem, sizeof(defitem), "%u", def);
    if(list == NULL)
        list = defitem;
    iecSINT **items = icsRxSplit(list, "/\\s*,\\s*/");
    iecINT count = 0;
    if(items != NULL) {
        for(iecINT i=0; items[i] != NULL; i++)
            count++;
        *pu = count;
        iecSINT *err;
        ICS_SMEMORY(nItems, iecUDINT, count);
        if(nItems != NULL) {
            for(iecINT i=0; items[i] != NULL; i++)
                nItems[i] = strtol(items[i], &err, 0);
            return nItems;
        }
    }
    return NULL;
}

iecSINT *icsBin2Hexdump(iecBYTE *data, iecUDINT octets)
{
    ICS_SMEMORY(hex, iecSINT, octets * 3);
    if(hex == NULL)
        return NULL;
    iecUDINT i, c = 0;
    for(i=0; i < octets; i++) {
        iecUSINT o = *(data + i);
        if(i == 0)
            c = sprintf(hex, "%02x", o);
        else
            c += sprintf(hex + c, " %02x", o);
    }
    return hex;
}

iecUSINT *icsHexdump2Bin(iecSINT *hexdump, iecUDINT *pl)
{
    iecINT i, l;
    for(i=l=0; hexdump[i]; i++)
        if(!isspace(hexdump[i]))
            l++;
    ICS_SMEMORY(bin, iecUSINT, l);
    if(bin == NULL)
        return NULL;
    iecSINT item[4];
    iecINT si, j;
    for(i=j=si=0; hexdump[i]; i++) {
        if(isspace(hexdump[i]))
            continue;
        if(!isxdigit(hexdump[i]))
            break;
        item[si++] = hexdump[i];
        if(si == 2) {
            item[si] = '\0';
            bin[j++] = (uint8_t) strtoul(item, NULL, 16);
            si = 0;
        }
    }
    if(pl != NULL)
        *pl = (uint32_t) j;
    return bin;
}

iecSINT *icsRemoveQuotes(const iecSINT *s)
{
    if(s == NULL)
        return NULL;
    int l = strlen(s);
    if(l >= 2)
        if((s[0] == '\'' && s[l-1] == '\'') || (s[0] == '"' && s[l-1] == '"'))
            return icsStrndup(s+1, l-2);
    return icsStrdup(s);
}

IcsOpaque icsFreeStringArray(iecSINT **p)
{
    if(p != NULL) {
        int i;
        for(i=0; p[i] != NULL; i++)
            ICS_FREE(p[i]);
        ICS_FREE(p);
    }
}

iecSINT *icsStrdup(const iecSINT *s)
{
    int l = strlen(s);
    ICS_SMEMORY(ns, iecSINT, l + 1);
    return (ns == NULL ? NULL : strcpy(ns, s));
}

iecSINT *icsStrndup(const iecSINT *s, size_t n)
{
    ICS_SMEMORY(ns, iecSINT, n + 1);
    if(ns == NULL)
        return NULL;
    strncpy(ns, s, n)[n] = '\0';
    return ns;
}

iecUSINT icsGetOctet(const iecUSINT *p, int o)
{
    return *(p + o);
}
iecUSINT *icsGetOctets(const iecUSINT *p, int o, int l)
{
    ICS_SMEMORY(bytes, iecUSINT, l + 1);
    if(bytes == NULL)
        return NULL;
    memcpy(bytes, p + o, l);
    bytes[l] = '\0';
    return bytes;
}

iecUINT icsGetWord(const iecUSINT *p, int o, iecBOOL hostMode)
{
    iecUINT *p16 = (iecUINT *)(p + o);
    return hostMode ? htons(*p16) : *p16;
}
iecUINT *icsGetWords(const iecUSINT *p, int o, int n, iecBOOL hostMode)
{
    ICS_SMEMORY(words, iecUINT, n * 2);
    if(words == NULL)
        return NULL;
    int i;
    for(i=0; i < n; i++) {
        words[i] = icsGetWord(p, o, hostMode);
        o += 2;
    }
    return words;
}

iecUDINT icsGetTriple(const iecUSINT *p, int o, iecBOOL hostMode)
{
    ICS_IGNORE(hostMode);
    iecUSINT triple[4];
    triple[0] = '\0';
    triple[1] = *(p + o);
    triple[2] = *(p + o + 1);
    triple[3] = *(p + o + 2);
    iecUDINT *p32 = (iecUDINT *) triple;
    return *p32;
}
iecUDINT *icsGetTriples(const iecUSINT *p, int o, int n, iecBOOL hostMode)
{
    ICS_SMEMORY(dwords, iecUDINT, n * 4);
    if(dwords == NULL)
        return NULL;
    int i;
    for(i=0; i < n; i++) {
        dwords[i] = icsGetTriple(p, o, hostMode);
        o += 3;
    }
    return dwords;
}

iecUDINT icsGetDWord(const iecUSINT *p, int o, iecBOOL hostMode)
{
    iecUDINT *p32 = (iecUDINT *)(p + o);
    return hostMode ? htonl(*p32) : *p32;
}
iecUDINT *icsGetDWords(const iecUSINT *p, int o, int n, iecBOOL hostMode)
{
    ICS_SMEMORY(dwords, iecUDINT, n * 4);
    if(dwords == NULL)
        return NULL;
    int i;
    for(i=0; i < n; i++) {
        dwords[i] = icsGetDWord(p, o, hostMode);
        o += 4;
    }
    return dwords;
}

iecULINT icsGetQWord(const iecUSINT *p, int o, iecBOOL hostMode)
{
    iecULINT *p64 = (iecULINT *)(p + o);
    return hostMode ? htonl(*p64) : *p64;
}
iecULINT *icsGetQWords(const iecUSINT *p, int o, int n, iecBOOL hostMode)
{
    ICS_SMEMORY(qwords, iecULINT, n * 4);
    if(qwords == NULL)
        return NULL;
    int i;
    for(i=0; i < n; i++) {
        qwords[i] = icsGetQWord(p, o, hostMode);
        o += 4;
    }
    return qwords;
}

IcsOpaque *icsGetItem(iecUSINT *p, int o, int l)
{
    return icsGetOctets(p, o, l);
}
IcsOpaque *icsGetItems(iecUSINT *p, int o, int l, int n)
{
    return icsGetOctets(p, o, l * n);
}

iecULINT icsGetBits(iecUSINT *p, int o, int l, iecBOOL hostMode)
{
    int bo = o & 7;
    int needed = (bo + l) >> 3;
    if(((bo + l) & 7) > 0)
        needed++;
    int offset = o >> 3;
    int shift = 8 - ((o + l) & 7);
    if(shift == 8)
        shift = 0;
    int mask = l & 7;
    if(mask == 0)
        mask = 8;
    iecULINT v = 0;

    if(needed == 1) {
        register iecUSINT uc = p[offset];
        uc >>= shift;
        uc &= (0xFF >> (8 - mask));
        v = (iecULINT) uc;
    }
    else
    if(needed == 2) {
        register unsigned short int us = *((unsigned short int *)(p + offset));
        us >>= shift;
        us &= (0xFFFF >> (8 - mask));
        v = (iecULINT) (hostMode ? ntohs(us) : us);
    }
    else
    if(needed > 2 && needed < 5) {
        register iecULINT ul = *((iecULINT *)(p + offset));
        ul >>= shift;
        ul &= (0xFFFFFFFF >> (8 - mask));
        v = hostMode ? ntohl(ul) : ul;
    }

    return v;
}

static const unsigned int primes[] = {
    53, 97, 193, 389, 769, 1543, 3079, 6151, 12289, 24593, 49157, 98317,
    196613, 393241, 786433, 1572869, 3145739, 6291469, 12582917, 25165843,
    50331653, 100663319, 201326611, 402653189, 805306457, 1610612741
};

static unsigned elf_hash(const char *s, int l)
{
    unsigned h = 0;
    for(int i=0; i < l; i++) {
        h = (h << 4) + s[l];
        unsigned hi = h & 0xF0000000;             
        if(hi != 0)
            h ^= hi >> 24; 
        h &= ~hi;
    }
    return h;
}

static unsigned sdbm_hash(const char *s, int l)
{
    unsigned h = 0;
    for(int i=0; i < l; i++) 
        h = s[i] + (h << 6) + (h << 16) - h;
    return h;
}

static unsigned djb2_hash(const char *s, int l)
{
    unsigned h = 5381;
    for(int i=0; i < l; i++) 
        h = ((h << 5) + h) + s[i];
    return h;
}

static iecULINT _hash(IcsHashAlgorithm type, const iecSINT *str)
{
    iecULINT h;
    iecSINT *s = (iecSINT *) str;
    switch(type) {
        case SCHA_SDBM:     h = sdbm_hash(s, strlen(s));    break;
        case SCHA_ELF:      h = elf_hash(s, strlen(s));     break;
        case SCHA_DJB2:     h = djb2_hash(s, strlen(s));    break;
        case SCHA_DEFAULT:
        default:            h = elf_hash (s, strlen(s));    break;
    }
    return h;
}

static int _grow(IcsHash *h)
{
    if(h->p + 1 > sizeof(primes) / sizeof(primes[0]))
        return -1;

    iecULINT size = primes[h->p + 1];
    ICS_SMEMORY(*items, IcsHashItem, sizeof(void *) * size);
    if(items == NULL)
        return -1;
    h->p++;
    iecULINT u;
    for(u=0; u < h->s; u++) {
        IcsHashItem *hi;
        while((hi = h->items[u]) != NULL) {
            h->items[u] = hi->n;
            iecULINT index = hi->h % size;
            hi->n = items[index];
            items[index] = hi;
        }
    }
    ICS_FREE(h->items);
    h->items = items;
    h->s = size;
    h->ts = size * h->t / 100;
    return 0;
}

IcsHash *icsHashCreate(int initialSize, int threshold, IcsHashAlgorithm algorithm)
{
    unsigned size = initialSize;
    unsigned thresh = threshold;
    IcsHashAlgorithm algo = algorithm;
    if(algo == SCHA_DEFAULT)
        algo = (IcsHashAlgorithm) icsConfigGetNumber("libics.hashalgorithm");
    unsigned pi;
    iecULINT p = 0;
    for(pi=0; pi < sizeof(primes) / sizeof(primes[0]); pi++)
        if((p = primes[pi]) > size)
            break;
    if(p == 0)
        return NULL;
    ICS_TMEMORY(h, IcsHash);
    if(h == NULL)
        return NULL;
    ICS_SMEMORY(*newItems, IcsHashItem, sizeof(void *) * p);
    if((h->items = newItems) == NULL) {
        ICS_FREE(h);
        return NULL;
    }
    h->s = p;
    h->p = pi;
    h->t = thresh;
    h->ts = size * thresh / 100;
    h->a = algo;
    return h;
}

int icsHashSetItem(IcsHash *h, const iecSINT *key, const IcsOpaque *value)
{
    if(h == NULL || key == NULL)
        return 0;
    iecULINT hl = _hash(h->a, key);
    iecULINT index = hl % h->s;
    if(h->l + 1 > h->ts) {
        if(_grow(h) == 0)
            return icsHashSetItem(h, key, value);
        else
            return -1;
    }
    ICS_TMEMORY(hi, IcsHashItem);
    if(hi == NULL)
        return -1;
    if(++h->l > h->hw)
        h->hw = h->l;
    hi->h = hl;
    hi->k = icsStrdup(key);
    hi->v = (IcsOpaque *) value;
    hi->n = h->items[index];
    if(hi->n != NULL)
        h->x++;
    h->items[index] = hi;
    return 0;
}

IcsOpaque *icsHashGetItem(IcsHash *h, const iecSINT *key)
{
    if(h == NULL || key == NULL)
        return NULL;
    iecULINT hl = _hash(h->a, key);
    iecULINT index = hl % h->s;
    IcsHashItem *hi = h->items[index];
    while(hi != NULL) {
        if(hi->h == hl && strcmp(hi->k, key) == 0)
            return hi->v;
        hi = hi->n;
    }
    return NULL;
}

IcsOpaque *icsHashDeleteItem(IcsHash *h, const iecSINT *key)
{
    if(h == NULL || key == NULL)
        return NULL;
    iecULINT hl = _hash(h->a, key);
    iecULINT index = hl % h->s;
    IcsHashItem **phi = &(h->items[index]);
    IcsHashItem *hi = *phi;
    IcsHashItem *prev = NULL;
    IcsHashItem *hit = NULL;
    while(hit == NULL && hi != NULL) {
        if(hi->h == hl && strcmp(hi->k, key) == 0) {
            hit = hi;
            *phi = hi->n;
            if(hi == h->ii)
                h->ii = prev;
            h->l--;
        }
        phi = &(hi->n);
        prev = hi;
        hi = hi->n;
    }
    if(hit == NULL)
        return NULL;
    IcsOpaque *v = hit->v;
    ICS_FREE(hit->k);
    ICS_FREE(hit);
    return v;
}

IcsOpaque *icsHashFirstItem(IcsHash *h, iecSINT **key)
{
    if(h == NULL)
        return NULL;
    for(h->iu=0; h->iu < h->s; h->iu++) {
        IcsHashItem *hi = h->items[h->iu];
        if(hi != NULL) {
            h->ii = hi;
            if(key != NULL)
                *key = hi->k;
            return hi->v;
        }
    }
    return NULL;
}

IcsOpaque *icsHashNextItem(IcsHash *h, iecSINT **key)
{
    if(h == NULL)
        return NULL;
    if(h->ii != NULL && h->ii->n != NULL) {
        IcsHashItem *hi = h->ii->n;
        if(key != NULL)
            *key = hi->k;
        IcsOpaque *v = hi->v;
        h->ii = hi->n;
        return v;
    }
    for(h->iu++; h->iu < h->s; h->iu++) {
        IcsHashItem *hi = h->items[h->iu];
        if(hi != NULL) {
            h->ii = hi;
            if(key != NULL)
                *key = hi->k;
            return hi->v;
        }
    }
    return NULL;
}

int icsHashFree(IcsHash *h)
{
    if(h == NULL)
        return -1;
    iecULINT u;
    for(u=0; u < h->s; u++) {
        IcsHashItem *hi = h->items[u];
        while(hi != NULL) {
            if(hi->v != NULL)
                ICS_FREE(hi->v);
            IcsHashItem *prev = hi;
            hi = hi->n;
            ICS_FREE(prev->k);
            ICS_FREE(prev);
        }
    }
    ICS_FREE(h->items);
    ICS_FREE(h);
    return 0;
}

IcsFifo *icsFifoCreate(void)
{
    ICS_TMEMORY(newFifo, IcsFifo);
    return newFifo;
}

int icsFifoFree(IcsFifo *fifo)
{
    int deleted = 0;
    if(fifo != NULL) {
        IcsFifoItem *item = fifo->h;
        if(item != NULL) do {
            IcsFifoItem *next = item->n;
            ICS_FREE(item->v);
            ICS_FREE(item);
            item = next;
            deleted++;
        } while(item != fifo->h);
        ICS_FREE(fifo);
    }
    return deleted;
}

int icsFifoPush(IcsFifo *fifo, IcsOpaque *v)
{
    IcsFifoItem *new = NULL;
    if(fifo != NULL) {
        ICS_TMEMORY(newItem, IcsFifoItem);
        if(newItem != NULL) {
            if(fifo->h == NULL) {
                fifo->h = fifo->t = newItem;
                newItem->p = newItem->n = newItem;
            }
            else {
                fifo->t->n = newItem;
                newItem->p = fifo->t;
                fifo->t = newItem;
                newItem->n = fifo->h;
                fifo->h->p = newItem;
            }
            newItem->v = v;
            new = newItem;
        }
    }
    return new == NULL ? 0 : 1;
}

IcsOpaque *icsFifoPop(IcsFifo *fifo)
{
    IcsOpaque *v = NULL;
    if(fifo != NULL && fifo->t != NULL) {
        v = fifo->t->v;
        if(fifo->h == fifo->t) {
            ICS_FREE(fifo->h);
            fifo->h = fifo->t = NULL;
        }
        else {
            fifo->t = fifo->t->p;
            fifo->h->p = fifo->t;
            fifo->t->n = fifo->h;
        }
    }
    return v;
}

// sdw - need mutex here
static IcsHash *rxCache;

static IcsRx *_rxcreate(const iecSINT *rx, const iecSINT *flags)
{
    int o = 0;
    int g = 0;
    int i;
    if(flags != NULL) {
        for(i=0; flags[i]; i++) {
            switch(flags[i]) {
                case 'g': g = 1;                        break;
                case 'i': o |= PCRE_CASELESS;           break;
                case 'm': o |= PCRE_MULTILINE;          break;
                case 's': o |= PCRE_DOTALL;             break;
                case 'x': o |= PCRE_EXTENDED;           break;
                case 'n': o |= PCRE_NEWLINE_ANYCRLF;    break;
            }
        }
    }

    int eo;
    const iecSINT *e;
    pcre *p = pcre_compile(rx, o, &e, &eo, NULL);
    if(p == NULL)
        return NULL;
    const char *err;
    pcre_extra *pe = pcre_study(p, 0, &err);

    ICS_TMEMORY(rp, IcsRx);
    rp->p = p;
    rp->pe = pe;
    rp->global = g;
    return rp;
}

static void _rxfree(IcsRx *rp)
{
    if(rp != NULL) {
        if(rp->pe != NULL)
            pcre_free(rp->pe);
        if(rp->p != NULL)
            pcre_free(rp->p);
        ICS_FREE(rp);
    }
}

static IcsRx *_getrx(const iecSINT *rx)
{
    IcsRx *rp = NULL;
    ICS_LOCK;
    if(rxCache == NULL)
        rxCache = icsHashCreate(64, 90, SCHA_DEFAULT);
    if(rxCache != NULL) {
        rp = icsHashGetItem(rxCache, rx);
        if(rp == NULL && *rx == '/') {
            iecSINT *s = icsStrdup(rx + 1);
            if(s != NULL) {
                iecSINT *ss = strrchr(s, '/');
                if(ss != NULL) {
                    *ss++ = '\0';
                    if((rp = _rxcreate(s, ss)) != NULL)
                        icsHashSetItem(rxCache, rx, rp);
                }
                ICS_FREE(s);
            }
        }
    }
    ICS_UNLOCK;
    return rp;
}

void icsRxFreeCache(void)
{
    ICS_LOCK;
    if(rxCache != NULL) {
        iecSINT *key;
        IcsRx *rx = icsHashFirstItem(rxCache, &key);
        while(rx != NULL) {
            rx = icsHashDeleteItem(rxCache, key);
            _rxfree(rx);
            rx = icsHashNextItem(rxCache, &key);
        }
        icsHashFree(rxCache);
        rxCache = NULL;
    }
    ICS_UNLOCK;
}

iecSINT **icsRxMatch(const iecSINT *s, const iecSINT *rx)
{
    IcsRx *rp = _getrx(rx);
    if(rp == NULL || s == NULL)
        return NULL;
    int len = strlen(s);
    int ovector[128];
    int rc = pcre_exec(rp->p, rp->pe, s, len, 0, 0, ovector, 128);
    if(rc == PCRE_ERROR_NOMATCH)
        return NULL;
    ICS_SMEMORY(*m, iecSINT, sizeof(void *) * (rc + 1));
    int i;
    for(i=0; i < rc; i++) {
        int b = ovector[2*i];
        int l = ovector[2*i+1]-b;
        m[i] = icsStrndup(s+b, l);
    }
    m[rc] = NULL;
    return m;
}

iecSINT *icsRxReplace(const iecSINT *s, const iecSINT *r, const iecSINT *rx)
{
    IcsRx *rp = _getrx(rx);
    if(rp == NULL || s == NULL || r == NULL)
        return NULL;
    iecSINT **m = icsRxMatch(rx, s);
    if(m == NULL)
        return icsStrdup(s);
    int mc;
    for(mc = 0; m[mc]; mc++)
        ICS_FREE(m[mc]);
    ICS_FREE(m);
    ICS_SMEMORY(ns, iecSINT, strlen(s) + mc * strlen(r) + 8);
    *ns = '\0';
    int b = 0, rc, len = strlen(s), ovector[16];
    while((rc = pcre_exec(rp->p, rp->pe, s, len, b, 0, ovector, 16)) == 1) {
        int l = ovector[0]-b;
        iecSINT *chunk = icsStrndup(s+b, l);
        strcat(ns, chunk);
        ICS_FREE(chunk);
        strcat(ns, r);
        b = ovector[1];
        if(rp->global == 0)
            break;
    }
    return ns;
}

iecSINT **icsRxSplit(const iecSINT *s, const iecSINT *rx)
{
    IcsRx *rp = _getrx(rx);
    if(rp == NULL || s == NULL)
        return NULL;
    ICS_SMEMORY(*sp, iecSINT, sizeof(void *) * 128);
    int b = 0, rc, len = strlen(s), ovector[128], j = 0;
    while(j < 128 && (rc = pcre_exec(rp->p, rp->pe, s, len, b, 0, ovector, 128)) == 1) {
        int l = ovector[0]-b;
        sp[j++] = icsStrndup(s+b, l);
        b = ovector[1];
    }
    if(b < len)
        sp[j++] = icsStrndup(s+b, len-b);
    sp[j] = NULL;

    return sp;
}

IcsQueue *icsQueueCreate(int max, int ttl)
{
    ICS_IGNORE(max);
    ICS_IGNORE(ttl);
    ICS_TMEMORY(queue, IcsQueue);
    return queue;
}

int icsQueueAddItem(IcsQueue *q, const IcsOpaque *ptr, size_t sz)
{
    if(q == NULL || ptr == NULL)
        return -1;
    ICS_TMEMORY(qi, IcsQueueItem);
    if(qi == NULL)
        return -1;
    if(sz == (size_t) -1) {
        qi->ptr = (IcsOpaque *) ptr;
        qi->sz = sz;
    }
    else {
        ICS_SMEMORY(newPtr, IcsOpaque, sz);
        qi->ptr = newPtr;
        if(qi->ptr == NULL) {
            ICS_FREE(qi);
            return -1;
        }
        memcpy(qi->ptr, ptr, qi->sz = sz);
    }

    if(q->t == NULL)
        q->t = q->h = qi;
    else
        q->h = q->h->n = qi;

    ++q->put;

    iecULINT total = q->put - q->get;
    if(total > q->max)
        q->max = total;

    return 1;
}

IcsOpaque *icsQueueGetItem(IcsQueue *q, size_t *psz)
{
    if(q == NULL || q->t == q->h || psz == NULL)
        return NULL;
    IcsQueueItem *qi = q->t;
    *psz = qi->sz;
    IcsOpaque *ptr = qi->ptr;

    q->t = q->t->n;

    ++q->get;
    ICS_FREE(qi);
    return ptr;
}

int icsQueueIsEmpty(IcsQueue *q)
{
    q->h = NULL;
    iecULINT total = q->put - q->get;
    return total == 0 ? 1 : 0;
}

int icsQueueFree(IcsQueue *q)
{
    if(q == NULL)
        return -1;
    IcsQueueItem *qi = q->t, *n;
    if(qi != NULL) do {
        n = qi->n;
        ICS_FREE(qi);
    } while((qi = n) != NULL);
    ICS_FREE(q);
    return 0;
}

