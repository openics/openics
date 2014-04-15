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

#include "ics.h"

#include "icscommon.h"
#include "icsdnp3.h"
#include "icsenip.h"
#include "icscip.h"
#include "icsmodbus.h"

static IcsProtocolTable protocolTable[ICS_PROTO_ALL];

void *(*_icsMalloc)(size_t size) = malloc;
void  (*_icsFree)(void *ptr)     = free;

FILE *icsMemFp			  = NULL;
char *icsMemFilename	  = NULL;

FILE *icsHexFp			  = NULL;
char *icsHexFilename	  = NULL;

FILE *icsLogFp			  = NULL;
char *icsLogFilename	  = NULL;

iecUINT transactionMaxima[ICS_PROTO_ALL];
IcsLogLevel logLevel = ICS_LOGLEVEL_ERROR;

static iecBOOL initialized  = iecFALSE;
static IcsHash *configItems = NULL;

IcsOpaque *icsMalloc(size_t size)
{
	IcsOpaque *ptr = (*_icsMalloc)(size);
	if(ptr != NULL)
		memset(ptr, 0, size);
	return ptr;
}

IcsOpaque icsFree(IcsOpaque *ptr)
{
	if(ptr != NULL)
		_icsFree(ptr);
}

iecBOOL icsConfigAddItem(iecSINT *name, iecSINT *s, iecLREAL d, iecBOOL override)
{
	if(configItems == NULL)
		configItems = icsHashCreate(32, 90, SCHA_DEFAULT);
	iecBOOL result = iecFALSE;
	if(configItems != NULL && name != NULL) {
		IcsValue *value = icsConfigGetItem(name);
		if(value != NULL) {
			if(override == iecFALSE)
				return iecFALSE;
			icsHashDeleteItem(configItems, name);
			ICS_FREE(value);
		}
		ICS_TMEMORY(newValue, IcsValue);
		if(newValue != NULL) {
			if(s != NULL) {
				newValue->type = ICS_VALUETYPE_STRING;
				newValue->s = icsStrdup(s);
			} else {
				newValue->type = ICS_VALUETYPE_NUMERIC;
				newValue->d = d;
			}
			result = (icsHashSetItem(configItems, name, newValue) == 0);
		}
	}
	return result;
}

IcsValue *icsConfigGetItem(iecSINT *name)
{
	IcsOpaque *value = NULL;
	if(configItems != NULL)
		value = icsHashGetItem(configItems, name);
	return value;
}

iecBOOL icsConfigAddString(iecSINT *name, iecSINT *s, iecBOOL override)
{
	iecBOOL r = iecFALSE;
	if(name != NULL && s != NULL)
		r = icsConfigAddItem(name, s, 0, override);
	return r;
}

iecBOOL icsConfigAddNumber(iecSINT *name, iecLREAL d, iecBOOL override)
{
	iecBOOL r = iecFALSE;
	if(name != NULL)
		r = icsConfigAddItem(name, NULL, d, override);
	return r;
}

iecSINT *icsConfigGetString(iecSINT *name)
{
	iecSINT *s = NULL;
	if(name != NULL) {
		IcsValue *value = icsConfigGetItem(name);
		if(value != NULL)
			s = value->s;
	}
	return s;
}

iecLREAL icsConfigGetNumber(iecSINT *name)
{
	iecLREAL d = 0;
	if(name != NULL) {
		IcsValue *value = icsConfigGetItem(name);
		if(value != NULL)
			d = value->d;
	}
	return d;
}

iecBOOL icsInitialize(void *(*mallocFunction)(size_t size), void (*freeFunction)(void *ptr), char *(*configLoader)(char *name))
{
	ICS_LOCK;
	if(initialized++) {
		ICS_UNLOCK;
		return iecTRUE;
	}

	ICS_FETCH_CONFIG_NUMBER(configLoader, "libics.hashalgorithm");
	ICS_FETCH_CONFIG_STRING(configLoader, "libics.logtracefile");
	ICS_FETCH_CONFIG_NUMBER(configLoader, "libics.loglevel");

	if(mallocFunction != NULL)
		_icsMalloc = mallocFunction;
	if(freeFunction != NULL)
		_icsFree   = freeFunction;

	logLevel = (IcsLogLevel) icsConfigGetNumber("libics.loglevel");
	icsLog(ICS_LOGLEVEL_INFO, "Initializing ICS with default log level %d", logLevel);

	for(int i=0; i < ICS_PROTO_ALL; i++)
		transactionMaxima[i] = ICS_DEFAULT_MAXTRANS;

	ICS_STARTMEMTRACE();

	if(icsInitializeEnip(configLoader)) {
		protocolTable[ICS_PROTO_ENIP].parse     = icsParseEnip;
		protocolTable[ICS_PROTO_ENIP].probe     = icsProbeEnip;
	}

	if(icsInitializeCip(configLoader)) {
		protocolTable[ICS_PROTO_CIP].parse      = icsParseCip;
		protocolTable[ICS_PROTO_CIP].probe      = icsProbeCip;
	}

	if(icsInitializeDnp3(configLoader)) {
		protocolTable[ICS_PROTO_DNP3].parse     = icsParseDnp3;
		protocolTable[ICS_PROTO_DNP3].probe     = icsProbeDnp3;
	}

	if(icsInitializeModbus(configLoader)) {
		protocolTable[ICS_PROTO_MODBUS].parse   = icsParseModbus;
		protocolTable[ICS_PROTO_MODBUS].probe   = icsProbeModbus;
	}

	ICS_UNLOCK;
	return initialized = iecTRUE;
}

iecBOOL icsUninitialize(void)
{
	ICS_LOCK;
	if(!initialized) {
		ICS_UNLOCK;
		return iecTRUE;
	}
	icsUninitializeDnp3();
	icsUninitializeEnip();
	icsUninitializeCip();
	icsUninitializeModbus();
	if(icsHexFp != NULL) {
		fclose(icsHexFp);
		ICS_FREE(icsHexFilename);
	}
	if(icsLogFp != NULL) {
		fclose(icsLogFp);
		ICS_FREE(icsLogFilename);
	}
	icsRxFreeCache();
	ICS_STOPMEMTRACE();
	initialized = 0;
	ICS_UNLOCK;
	return iecTRUE;
}

iecUINT icsLog(IcsLogLevel level, const iecSINT *format, ...)
{
	if(level > logLevel)
		return 0;
	iecUDINT bytesWritten = 0;
	ICS_LOCK;
	if(icsLogFilename == NULL)
		icsLogFilename = icsConfigGetString("libics.logtracefile");
	if(icsLogFilename != NULL) {
		if(icsLogFp == NULL)
			icsLogFp = fopen(icsLogFilename, "a+");
		if(icsLogFp != NULL) {
			iecSINT now[32];
			time_t t = time(NULL);
			struct tm lt;
			localtime_r(&t, &lt);
			strftime(now, sizeof(now), "%Y-%d-%m %H:%M:%S ", &lt);
			bytesWritten = (iecUINT) fprintf(icsLogFp, now);
			va_list va;
			va_start(va, format);
			bytesWritten += (iecUINT) vfprintf(icsLogFp, format, va);
			va_end(va);
			if(format[strlen(format)-1] != '\n')
				bytesWritten += (iecUINT) fprintf(icsLogFp, "\n");
		}
	}
	ICS_UNLOCK;
	return bytesWritten;
}

IcsParseResult icsParse(IcsLayer startLayer, IcsProtocol protocol, IcsMode mode,
							iecBYTE *data, iecUDINT octets,
							IcsStack *stack)
{
	IcsParseResult result = ICS_RESULT_UNKNOWNPROTOCOL;

	if(protocol <= ICS_PROTO_NONE || protocol > ICS_PROTO_DETECT)
		return result;

	if(protocol == ICS_PROTO_DETECT) {
		protocol = ICS_PROTO_NONE;
		IcsProtocol p;
		for(p = ICS_PROTO_NONE + 1; p < ICS_PROTO_DETECT; p++) {
			protocol = protocolTable[p].probe(startLayer, data, octets);
			if(protocol != ICS_PROTO_NONE)
				break;
		}
	}
	if(protocol == ICS_PROTO_NONE)
		return result;

	stack->lastError = protocolTable[protocol].parse(startLayer, mode, data, octets, stack);
	return stack->lastError;
}

IcsStack *icsStackAllocate(void)
{
	ICS_TMEMORY(stack, IcsStack);
	return stack;
}

void icsStackFree(IcsStack *stack)
{
	if(stack != NULL) {
		icsTransactionPurge(stack, ICS_PROTO_ALL);
		ICS_FREE(stack);
	}
}

IcsProtocol icsProbe(IcsLayer startLayer, IcsProtocol protocol,
						 iecBYTE *data, iecUDINT octets)
{
	IcsProtocol result = ICS_PROTO_NONE;

	if(protocol <= ICS_PROTO_NONE || protocol > ICS_PROTO_DETECT)
		return result;

	if(protocol == ICS_PROTO_DETECT) {
		IcsProtocol p;
		for(p = ICS_PROTO_NONE + 1; p < ICS_PROTO_DETECT; p++) {
			result = protocolTable[p].probe(startLayer, data, octets);
			if(result != ICS_PROTO_NONE)
				break;
		}
	}
	else
		result = protocolTable[protocol].probe(startLayer, data, octets);

	return result;
}

IcsDetectItem *icsMunge(const iecSINT *keyword, const iecSINT *options)
{
	IcsDetectItem *item = NULL;
	if(strncmp(keyword, "dnp3", 4) == 0)
		item = icsMungeDnp3(keyword, options);
	else
	if(strncmp(keyword, "modbus", 6) == 0)
		item = icsMungeModbus(keyword, options);
	else
	if(strncmp(keyword, "enip", 4) == 0)
		item = icsMungeEnip(keyword, options);
	else
	if(strncmp(keyword, "cip", 3) == 0)
		item = icsMungeCip(keyword, options);
	return item;
}

void icsFreeDetectItem(IcsDetectItem *item)
{
	// TODO: don't duplicate globals and constants for each IcsDetectItem
	if(item != NULL) {
    	icsHashFree(item->globals);
		icsHashFree(item->constants);
		ICS_FREE(item->predicate);
		ICS_FREE(item);
	}
}

iecBOOL icsEvaluate(IcsDetectItem *item, IcsTransaction *transaction)
{
	iecBOOL result = iecFALSE;
	if(transaction != NULL && item != NULL) {
		IcsFifo *fifo = icsPredicateEvaluate(item->predicate, item->globals, item->constants, transaction->variables);
		if(fifo != NULL) {
			IcsPredicateValue *v = icsFifoPop(fifo);
			if(v != NULL) {
				if((v->type == SPVT_NUMERIC && v->d != 0) ||
				   (v->type == SPVT_ARRAY   && v->count > 0) ||
				   (v->type == SPVT_STRING  && v->s != NULL))
					result = iecTRUE;
				icsFreePredicateValue(&v);
			}
			while((v = icsFifoPop(fifo)) != NULL)
				icsFreePredicateValue(&v);
			icsFifoFree(fifo);
		}
	}
	return result;
}

IcsTransaction *icsTransactionNew(IcsStack *stack, IcsProtocol proto, iecSINT *key, IcsOpaque *(*initializer)(void), iecUINT ttl, iecBOOL pseudo)
{
	IcsTransaction *transaction = NULL;
	if(key == NULL)
		key = "defaultkey";
	if(stack != NULL) {
		IcsTransaction *prev = NULL;
		IcsTransaction **transactionPointer = &(stack->application.transactionRoots[proto]);
		transaction = stack->application.transactionRoots[proto];
		while(transaction != NULL) {
			if(transaction->next == NULL) {
				prev = transaction;
				transactionPointer = &(transaction->next);
				break;
			}
			transaction = transaction->next;
		}
		ICS_TMEMORY(newTransaction, IcsTransaction);
		transaction = *transactionPointer = newTransaction;
		if(transaction != NULL) {
			if(initializer != NULL && (transaction->opaque = (*initializer)()) == NULL) {
				ICS_FREE(transaction);
				*transactionPointer = NULL;
			}
			else {
				transaction->proto   = proto;
				transaction->prev    = prev;
				transaction->key     = icsStrdup(key);
				transaction->ttl     = ttl;
				transaction->pseudo  = pseudo;
				transaction->created = stack->time;
			}
		}
	}
	if(transaction != NULL)
		stack->application.outerKeys[proto] = transaction->key;
	else
		stack->application.outerKeys[proto] = NULL;
	return transaction;
}

IcsTransaction *icsTransactionGetLast(IcsStack *stack, IcsProtocol proto)
{
	IcsTransaction *transaction = NULL;
	if(stack != NULL) {
		IcsTransaction *scanner = stack->application.transactionRoots[proto];
		while(scanner != NULL) {
			if(scanner->next == NULL) {
				transaction = scanner;
				break;
			}
			scanner = scanner->next;
		}
	}
	return transaction;
}

IcsTransaction *icsTransactionGet(IcsStack *stack, IcsProtocol proto, iecSINT *key)
{
	IcsTransaction *transaction = NULL;
	if(key == NULL)
		key = "defaultkey";
	if(stack != NULL) {
		IcsTransaction *scanner = stack->application.transactionRoots[proto];
		while(scanner != NULL) {
			if(strcmp(scanner->key, key) == 0)
				transaction = scanner; // goal is to grab last one of same key;
			scanner = scanner->next;
		}
	}
	if(transaction != NULL)
		stack->application.outerKeys[proto] = transaction->key;
	else
		stack->application.outerKeys[proto] = NULL;
	return transaction;
}

IcsTransaction *icsTransactionPop(IcsStack *stack, IcsProtocol proto)
{
	IcsTransaction *transaction = NULL;
	if(stack != NULL) {
		IcsProtocol p;
		for(p = ICS_PROTO_NONE + 1; transaction == NULL && p < ICS_PROTO_DETECT; p++) {
			if(proto == ICS_PROTO_ALL || proto == p) {
				IcsTransaction *root = transaction = stack->application.transactionRoots[p];
				while(transaction != NULL) {
					IcsTransaction *next = transaction->next;
					if((stack->time - transaction->created) / 1000000 > transaction->ttl)
						transaction->timedout = iecTRUE;
					if(transaction->cooked || transaction->pseudo || transaction->timedout ||
					   transaction->parseFailure != ICS_RESULT_OK) {
						if(transaction == root) {
							if((root = next) != NULL)
								next->prev = NULL;
						}
						else {
							if(transaction->prev != NULL)
								transaction->prev->next = next;
							if(next != NULL)
								next->prev = transaction->prev;
						}
						break;
					}
					transaction = next;
				}
				stack->application.transactionRoots[p] = root;
			}
		}
	}
	return transaction;
}

iecBOOL icsTransactionMarkComplete(IcsTransaction *transaction)
{
	iecBOOL previousState = iecFALSE;
	if(transaction != NULL) {
		previousState = transaction->cooked;
		transaction->cooked = iecTRUE;
	}
	return previousState;
}

iecUDINT icsTransactionMarkAllComplete(IcsStack *stack, IcsProtocol proto)
{
	iecUDINT count = 0;
	if(stack != NULL) {
		IcsProtocol p;
		for(p = ICS_PROTO_NONE + 1; p < ICS_PROTO_DETECT; p++) {
			if(proto == ICS_PROTO_ALL || proto == p) {
				IcsTransaction *transaction = stack->application.transactionRoots[p];
				while(transaction != NULL) {
					transaction->cooked = iecTRUE;
					count++;
					transaction = transaction->next;
				}
			}
		}
	}
	return count;
}

IcsParseResult icsTransactionMarkFailed(IcsTransaction *transaction, IcsParseResult r)
{
	IcsParseResult previousState = ICS_RESULT_OK;
	if(transaction != NULL) {
		previousState = transaction->parseFailure;
		transaction->parseFailure = r;
	}
	return previousState;
}

iecUINT icsTransactionSetTTL(IcsTransaction *transaction, iecUINT ttl)
{
	iecUINT previousTTL = 0;
	if(transaction != NULL) {
		previousTTL = transaction->ttl;
		transaction->ttl = ttl;
	}
	return previousTTL;
}

iecBOOL icsTransactionFree(IcsTransaction *transaction)
{
	if(transaction != NULL) {
		switch(transaction->proto) {
			case ICS_PROTO_DNP3: {
				icsFreeDnp3(transaction->opaque);
			} break;
			case ICS_PROTO_ENIP: {
				icsFreeEnip(transaction->opaque);
			} break;
			case ICS_PROTO_CIP: {
				icsFreeCip(transaction->opaque);
			} break;
			case ICS_PROTO_MODBUS: {
				icsFreeModbus(transaction->opaque);
			} break;
			default: break;
		}
		icsFreePredicateHash(transaction->variables);
		ICS_FREE(transaction->key);
		ICS_FREE(transaction);
	}
	return iecTRUE;
}

iecUINT icsTransactionPurge(IcsStack *stack, IcsProtocol proto)
{
	iecUINT purgeCount  = 0;
	if(stack != NULL) {
		IcsProtocol p;
		for(p = ICS_PROTO_NONE + 1; p < ICS_PROTO_DETECT; p++) {
			if(proto == ICS_PROTO_ALL || proto == p) {
				IcsTransaction *transaction = stack->application.transactionRoots[p];
				while(transaction != NULL) {
					IcsTransaction *next = transaction->next;
					switch(p) {
						case ICS_PROTO_DNP3: {
							icsFreeDnp3(transaction->opaque);
						} break;
						case ICS_PROTO_ENIP: {
							icsFreeEnip(transaction->opaque);
						} break;
						case ICS_PROTO_CIP: {
							icsFreeCip(transaction->opaque);
						} break;
						case ICS_PROTO_MODBUS: {
							icsFreeModbus(transaction->opaque);
						} break;
						default: break;
					}
					icsFreePredicateHash(transaction->variables);
					ICS_FREE(transaction->key);
					ICS_FREE(transaction);
					transaction = next;
					purgeCount++;
				}
				stack->application.transactionRoots[p] = NULL;
			}
		}
	}
	memset(stack->application.outerKeys, 0, sizeof(stack->application.outerKeys));
	return purgeCount;
}

iecUINT icsSaveHex(iecBYTE *data, iecUDINT octets, iecUDINT o, IcsHexdumpStyle style, iecSINT *keyFormat, ...)
{
	ICS_LOCK
	iecUDINT bytesWritten = 0;
	if(icsHexFilename == NULL)
		icsHexFilename = icsConfigGetString("libics.hextracefile");
	if(icsHexFilename != NULL) {
		if(icsHexFp == NULL)
			icsHexFp = fopen(icsHexFilename, "a+");
	}
	if(icsHexFp != NULL) {
		va_list ap;
		va_start(ap, keyFormat);
		iecSINT message[1024];
		bytesWritten = vsnprintf(message, sizeof(message), keyFormat, ap);
		va_end(ap);
		static IcsHash *hexLabels = NULL;
		if(hexLabels == NULL)
			hexLabels = icsHashCreate(1024, 90, SCHA_DEFAULT);
		if(hexLabels != NULL) {
			if(icsHashGetItem(hexLabels, message) != NULL) {
				ICS_UNLOCK;
				return 0;
			}
			icsHashSetItem(hexLabels, message, message);
		}
		fprintf(icsHexFp, message);
		//printf(message);
		iecSINT *hex = icsBin2Hexdump(data, ICS_MAX(octets, o));
		if(hex != NULL) {
			if(style == ICS_HEXDUMP_QUOTED) {
				bytesWritten += fprintf(icsHexFp, "\"%s\"", hex);
				//printf("\"%s\"", hex);
			}
			else {
				bytesWritten += fprintf(icsHexFp, hex);
				//printf("%s", hex);
			}
			ICS_FREE(hex);
		}
		bytesWritten += fprintf(icsHexFp, "\n");
		//printf("\n");
	}
	ICS_UNLOCK
	return bytesWritten;
}
