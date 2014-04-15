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
 * Primary ICS library entry points.
 *
 */

#if !defined(_ics_h)
#define _ics_h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <ctype.h>
#include <time.h>
#include <math.h>
#include <arpa/inet.h>
#include "config.h"
#include <pthread.h>

#define ICS_IGNORE(V)		(void)(V)
#define ICS_MIN(a, b)		(a < b ? a : b)
#define ICS_MAX(a, b)		(a > b ? a : b)

#define ICS_FETCH_CONFIG_NUMBER(loader, name) 								\
	if(loader != NULL) { 													\
		char *err; 															\
		char *value; 														\
		if((value = (*configLoader)(name)) != NULL) { 						\
			icsConfigAddNumber(name, strtol(value, &err, 0), iecTRUE);  	\
			free(value); 													\
		} 																	\
	}

#define ICS_FETCH_CONFIG_STRING(loader, name) 								\
	if(loader != NULL) { 													\
		char *value; 														\
		if((value = (*configLoader)(name)) != NULL) { 						\
			icsConfigAddString(name, value, iecTRUE); 						\
			free(value); 													\
		} 																	\
	}

#ifdef PTHREAD_MUTEX_INITIALIZER
	#define ICS_LOCK_OBJECT(obj)											\
		static pthread_mutex_t fileScope ## obj = PTHREAD_MUTEX_INITIALIZER
	#define ICS_LOCK_ON(obj)												\
		pthread_mutex_lock(&fileScope ## obj)
	#define ICS_UNLOCK_ON(obj)												\
		pthread_mutex_unlock(&fileScope ## obj)
	#define ICS_LOCK 														\
		static pthread_mutex_t zemutex = PTHREAD_MUTEX_INITIALIZER; 		\
		pthread_mutex_lock(&zemutex);
	#define ICS_UNLOCK 														\
		pthread_mutex_unlock(&zemutex);
	#define ICS_SAFE(expression) {											\
		static pthread_mutex_t zemutex = PTHREAD_MUTEX_INITIALIZER; 		\
		pthread_mutex_lock(&zemutex);										\
		expression;															\
		pthread_mutex_unlock(&zemutex);										\
	}
#else
	#define ICS_LOCK_OBJECT(obj)
	#define ICS_LOCK_ON(obj)
	#define ICS_UNLOCK_ON(obj)
	#define ICS_LOCK
	#define ICS_UNLOCK
	#define ICS_SAFE(expression) expression;
#endif

#define ICS_STARTMEMTRACE()												\
	if(icsMemFp == NULL) {												\
		icsMemFilename = icsConfigGetString("libics.memtracefile");		\
		if(icsMemFilename != NULL)										\
			icsMemFilename = icsStrdup(icsMemFilename);					\
		if(icsMemFilename != NULL)										\
			icsMemFp = fopen(icsMemFilename, "w");						\
	}

#define ICS_STOPMEMTRACE()										\
	if(icsMemFp != NULL) {										\
		fclose(icsMemFp);										\
		icsMemFp = NULL;										\
		ICS_FREE(icsMemFilename)								\
	}

#define ICS_MEMTRACEADD(n, t, l)								\
	if(icsMemFp != NULL) {										\
		fprintf(icsMemFp, 										\
				"%08lx:+:"#t":%lu:%s:%s:%d\n",					\
			    (uint64_t) n, (uint64_t) l,						\
				__FILE__, __FUNCTION__, __LINE__);				\
	}

#define ICS_MEMTRACEDEL(n)										\
	if(icsMemFp != NULL) {										\
		fprintf(icsMemFp, "%08lx:-:::%s:%s:%d\n",				\
			    (uint64_t) n,									\
				__FILE__, __FUNCTION__, __LINE__);		    	\
	}

#define ICS_FREE(v)							\
	if(v != NULL) {							\
		ICS_MEMTRACEDEL(v);					\
		icsFree(v);							\
		v = NULL;							\
	}

#define ICS_FREELL(v, n) {					\
	while(v != NULL) {						\
		ICS_MEMTRACEDEL(v);					\
		void *next = v->n;					\
		icsFree(v);							\
		v = next;							\
	}										\
	v = NULL;								\
}

#define ICS_TMEMORY(v, t)                 	\
	t *v = icsMalloc(sizeof(t));			\
	if(v != NULL) {							\
		ICS_MEMTRACEADD(v, t, sizeof(t));	\
		memset(v, 0, sizeof(t));			\
	}

#define ICS_SMEMORY(v, t, n)              	\
	t *v = icsMalloc(n);					\
	if(v != NULL) {							\
		ICS_MEMTRACEADD(v, t, n);			\
		memset(v, 0, n);					\
	}

#define ICS_TMEMORY_P(v, t) 	 			\
	t *v = icsMalloc(sizeof(t));			\
	if(v == NULL) 							\
		return ICS_RESULT_OUTOFMEMORY;		\
	ICS_MEMTRACEADD(v, t, sizeof(t));		\
	memset(v, 0, sizeof(t));

#define ICS_SMEMORY_P(v, t, n) 				\
	t *v = icsMalloc(n);					\
	if(v == NULL) 							\
		return ICS_RESULT_OUTOFMEMORY;		\
	ICS_MEMTRACEADD(v, t, n);				\
	memset(v, 0, n);

#define ICS_DUPE(d, s, n)	{				\
	d = icsMalloc(n); 						\
	if(d == NULL) 							\
		return ICS_RESULT_OUTOFMEMORY; 		\
	ICS_MEMTRACEADD(v, iecUSINT *, n);		\
	memcpy(d, s, n); 						\
}

typedef void IcsOpaque;

#include "icsiec61131.h"
#include "icscommon.h"

typedef enum tagIcsProtocol {
	ICS_PROTO_NONE = 0,
	ICS_PROTO_DNP3,
	ICS_PROTO_ENIP,
	ICS_PROTO_CIP,
	ICS_PROTO_MODBUS,
	ICS_PROTO_DETECT,
	ICS_PROTO_ALL  	// must be last entry
} IcsProtocol;

typedef enum tagIcsProtocolPort {
	ICS_TCP_DNP3     = 20000,
	ICS_UDP_DNP3     = 20000,
	ICS_TCP_ENIP     = 44818,
	ICS_UDP_ENIP     = 2222,
	ICS_TCP_CIP      = 0, 	// CIP is basically always encapsulated
	ICS_UDP_CIP      = 0,
	ICS_TCP_MODBUS   = 502,
	ICS_UDP_MODBUS   = 0,
} IcsProtocolPort;

typedef enum tagIcsLayer {
	ICS_LAYER_LINK         = 0x0100,
	ICS_LAYER_INTERNET     = 0x0200,
	ICS_LAYER_TRANSPORT    = 0x0400,
	ICS_LAYER_APPLICATION  = 0x0800,
	ICS_LAYER_ENCAP		   = 0x1000,
	ICS_LAYER_PROTOMASK    = 0x00ff,
	ICS_LAYER_MASK         = 0xff00
} IcsLayer;

typedef enum tagIcsMode {
	ICS_MODE_RQ,
	ICS_MODE_RS,
	ICS_MODE_UNK
} IcsMode;

typedef enum tagIcsLogLevel {
	ICS_LOGLEVEL_ERROR = 0,
	ICS_LOGLEVEL_WARNING,
	ICS_LOGLEVEL_INFO,
	ICS_LOGLEVEL_DEBUG
} IcsLogLevel;

typedef enum tagIcsParseResult {
	ICS_RESULT_OK,
	ICS_RESULT_SHORT,
	ICS_RESULT_INVALID,
	ICS_RESULT_OUTOFMEMORY,
	ICS_RESULT_UNKNOWNPROTOCOL,
	ICS_RESULT_BADCHECKSUM,
	ICS_RESULT_UNKNOWNFUNCTION,
	ICS_RESULT_UNKNOWNITEM,
	ICS_RESULT_NOTIMPLEMENTED,
	ICS_RESULT_INVALIDCONTEXT,
	ICS_RESULT_INVALIDCODING,
	ICS_RESULT_UNSUPPORTEDLAYER,
	ICS_RESULT_NOTRANSACTION,
	ICS_RESULT_ENCAPREQUIRED,
	ICS_RESULT_LIMITEXCEEDED,
	ICS_RESULT_FUNCTIONIGNORED
} IcsParseResult;

typedef enum tagIcsValueType {
	ICS_VALUETYPE_NONE,
	ICS_VALUETYPE_NUMERIC,
	ICS_VALUETYPE_STRING
} IcsValueType;

typedef enum tagIcsHexdumpStyle {
	ICS_HEXDUMP_PLAIN,
	ICS_HEXDUMP_QUOTED
} IcsHexdumpStyle;

typedef struct tagIcsVector {
	iecUDINT x;
	iecUDINT y;
} IcsVector;

typedef struct tagIcsValue {
	IcsValueType type;
	iecLREAL d;
	iecSINT *s;
} IcsValue;

typedef struct tagIcsNumericAssociation {
	iecUDINT value;
	iecSINT *name;
} IcsNumericAssociation;

typedef struct tagIcsStringAssociation {
	iecSINT *value;
	iecSINT *name;
} IcsStringAssociation;

typedef struct tagIcsVlan {
	iecUINT pcp;
	iecUINT cvi;
	iecUINT vid;
	struct tagIcsVlan *next;
} IcsVlan;

typedef struct tagIcsTransaction {
	IcsProtocol proto;
	IcsHash    *variables;
	IcsOpaque  *opaque;
	iecSINT    *key;
	iecUINT     ttl;
	iecLTIME    created;
	iecBOOL     pseudo;
	iecBOOL     cooked;
	iecBOOL     timedout;
	IcsParseResult parseFailure;
	struct tagIcsTransaction *prev;
	struct tagIcsTransaction *next;
} IcsTransaction;

typedef struct tagIcsStack {
	iecLTIME time;
	IcsParseResult lastError;
	struct IcsLinkLayer {
		iecSINT  srcmac[12];
		iecSINT  dstmac[12];
		IcsVlan *vlan;
		iecUINT  protocol;
		iecUDINT crc;
	} link;
	struct IcsInternetLayer {
		iecUDINT srcip;
		iecUDINT dstip;
		iecUINT  protocol;
	} internet;
	struct IcsTransportLayer {
		iecUINT srcport;
		iecUINT dstport;
	} transport;
	struct IcsApplicationLayer {
		IcsProtocol primaryProtocol;
		IcsTransaction *transactionRoots[ICS_PROTO_ALL];
		iecSINT *outerKeys[ICS_PROTO_ALL];
	} application;
} IcsStack;

typedef struct tagIcsDetectItem {
	IcsProtocol protocol;
	IcsHash *globals;
	IcsHash *constants;
	iecSINT  *predicate;
	iecUDINT  offset;
} IcsDetectItem;

typedef struct tagIcsProtocolTable {
	IcsParseResult (*parse)(IcsLayer startLayer, IcsMode mode, iecBYTE *data, iecUDINT octets, IcsStack *stack);
	IcsProtocol    (*probe)(IcsLayer startLayer, iecBYTE *data, iecUDINT octets);
} IcsProtocolTable;

extern FILE *icsMemFp;
extern char *icsMemFilename;

extern FILE *icsHexFp;
extern char *icsHexFilename;

extern FILE *icsLogFp;
extern char *icsLogFilename;

#define ICS_DEFAULT_MAXTRANS	1024
extern iecUINT transactionMaxima[];
extern IcsLogLevel logLevel;

IcsOpaque           *icsMalloc(size_t size);
void                 icsFree(IcsOpaque *ptr);

IcsParseResult       icsParse(IcsLayer startLayer, IcsProtocol protocol, IcsMode mode,
							  iecBYTE *data, iecUDINT octets, IcsStack *stack);

IcsProtocol          icsProbe(IcsLayer startLayer, IcsProtocol protocol,
						      iecBYTE *data, iecUDINT octets);

IcsDetectItem       *icsMunge(const iecSINT *keyword, const iecSINT *options);
void                 icsFreeDetectItem(IcsDetectItem *item);

IcsStack            *icsStackAllocate(void);
void                 icsStackFree(IcsStack *);

IcsTransaction      *icsTransactionNew(IcsStack *stack, IcsProtocol proto, iecSINT *key, IcsOpaque *(*initializer)(void), iecUINT ttl, iecBOOL pseudo);
IcsTransaction      *icsTransactionGet(IcsStack *stack, IcsProtocol proto, iecSINT *key);
IcsTransaction      *icsTransactionGetLast(IcsStack *stack, IcsProtocol proto);
IcsTransaction      *icsTransactionPop(IcsStack *stack, IcsProtocol proto);
iecUINT				 icsTransactionSetTTL(IcsTransaction *transaction, iecUINT ttl);
iecBOOL              icsTransactionMarkComplete(IcsTransaction *transaction);
iecUDINT             icsTransactionMarkAllComplete(IcsStack *stack, IcsProtocol proto);
IcsParseResult       icsTransactionMarkFailed(IcsTransaction *transaction, IcsParseResult r);
iecUINT              icsTransactionPurge(IcsStack *stack, IcsProtocol proto);
iecBOOL              icsTransactionFree(IcsTransaction *transaction);

iecBOOL              icsConfigAddItem(iecSINT *name, iecSINT *s, iecLREAL d, iecBOOL override);
iecBOOL              icsConfigAddString(iecSINT *name, iecSINT *s, iecBOOL override);
iecBOOL              icsConfigAddNumber(iecSINT *name, iecLREAL d, iecBOOL override);
IcsValue            *icsConfigGetItem(iecSINT *name);
iecSINT             *icsConfigGetString(iecSINT *name);
iecLREAL             icsConfigGetNumber(iecSINT *name);

iecBOOL			     icsInitialize(void *(*mallocFunction)(size_t size), void (*freeFunction)(void *ptr), char *(*configLoader)(char *name));
iecBOOL			     icsUninitialize(void);

iecBOOL			     icsEvaluate(IcsDetectItem *item, IcsTransaction *transaction);

iecUINT              icsLog(IcsLogLevel level, const iecSINT *format, ...);

iecUINT              icsSaveHex(iecBYTE *data, iecUDINT octets, iecUDINT o, IcsHexdumpStyle style, iecSINT *keyFormat, ...);

#endif

