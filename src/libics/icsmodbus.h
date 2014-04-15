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
 * MODBUS Primitives.
 *
 */
#if !defined(_icsmodbus_h)
#define _icsmodbus_h

#include "ics.h"
#include "icspredicate.h"

#define MODBUS_HDR_LEN	8

#define MODBUS_PREDICATE_FALSE       "0"
#define MODBUS_PREDICATE_TRUE        "1"
#define MODBUS_PREDICATE_FUNCTION    "modbus.header.function in sig.functions"
#define MODBUS_PREDICATE_TRANSACTION "modbus.header.transactionId in sig.transactions"
#define MODBUS_PREDICATE_UNITID      "modbus.header.unitId in sig.units"
#define MODBUS_PREDICATE_STATUS      "modbus.response.status in sig.statuses"
#define MODBUS_PREDICATE_CLASS       "modbus.header.functionClass in sig.classes"
#define MODBUS_PREDICATE_SUBTYPE     "modbus.header.functionSubtype in sig.subtypes"
#define MODBUS_PREDICATE_DIAGCODE    "modbus.request.diagCode in sig.diagcodes"
#define MODBUS_PREDICATE_SUBCODE     "modbus.request.subCode in sig.subcodes"
#define MODBUS_PREDICATE_MEICODE     "modbus.request.mei in sig.meicodes"

typedef enum tagModbusFunction {
	MODBUS_FUNC_READCOILS	      = 0x01,
	MODBUS_FUNC_READDISCINPUTS    = 0x02,
	MODBUS_FUNC_READHOLDREGS      = 0x03,
	MODBUS_FUNC_READINPUTREGS     = 0x04,
	MODBUS_FUNC_WRITESINGLECOIL   = 0x05,
	MODBUS_FUNC_WRITESINGLEREG    = 0x06,
	MODBUS_FUNC_READEXCSTATUS     = 0x07,
	MODBUS_FUNC_DIAGNOSTIC        = 0x08,
	MODBUS_FUNC_GETCOMEVTCOUNTER  = 0x0b,
	MODBUS_FUNC_GETCOMEVTLOG      = 0x0c,
	MODBUS_FUNC_WRITEMULTCOILS    = 0x0f,
	MODBUS_FUNC_WRITEMULTREGS     = 0x10,
	MODBUS_FUNC_REPORTSLAVEID     = 0x11,
	MODBUS_FUNC_READFILERECORD    = 0x14,
	MODBUS_FUNC_WRITEFILERECORD   = 0x15,
	MODBUS_FUNC_MASKWRITEREG      = 0x16,
	MODBUS_FUNC_READWRITEMULTREGS = 0x17,
	MODBUS_FUNC_READFIFOQUEUE     = 0x18,
	MODBUS_FUNC_ENCAPIFACETRANS   = 0x2b,
	MODBUS_FUNC_MASK              = 0x7f,
	MODBUS_FUNC_ERRORMASK         = 0x80
} ModbusFunction;

typedef enum tagModbusStatus {
	MODBUS_STAT_OK                     = 0x00,
	MODBUS_STAT_ILLEGALFUNCTION        = 0x01,
	MODBUS_STAT_ILLEGALDATAADDRESS     = 0x02,
	MODBUS_STAT_ILLEGALDATAVALUE       = 0x03,
	MODBUS_STAT_SLAVEDEVICEFAILURE     = 0x04,
	MODBUS_STAT_ACKNOWLEDGE            = 0x05, // time intensive, use poll
	MODBUS_STAT_SLAVEDEVICEBUSY        = 0x06,
	MODBUS_STAT_MEMORYPARITYERROR      = 0x08,
	MODBUS_STAT_GATEWAYPATHUNAVAILABLE = 0x0a,
	MODBUS_STAT_GATEWAYUNRESPONSIVE    = 0x0b
} ModbusStatus;

typedef enum tagModbusFunctionClass {
	MODBUS_CLASS_NONE      = 0x00,
	MODBUS_CLASS_PUBLIC    = 0x10,
	MODBUS_CLASS_USER      = 0x20,
	MODBUS_CLASS_MASK      = 0xf0
} ModbusFunctionClass;

typedef enum tagModbusFunctionSubtype {
	MODBUS_CLSUB_NONE      = 0x00,
	MODBUS_CLSUB_RESERVED  = 0x01,
	MODBUS_CLSUB_WELLKNOWN = 0x02,
	MODBUS_CLSUB_UNUSED    = 0x03,
	MODBUS_CLSUB_ENCAP     = 0x04,
	MODBUS_CLSUB_TYPEMASK  = 0x0f
} ModbusFunctionSubtype;

typedef enum tagModbusDiagnosticCode {
	MODBUS_DIAG_GETQUERYDATA       = 0x00,
	MODBUS_DIAG_RESTART            = 0x01,
	MODBUS_DIAG_GETDIAGREGISTER    = 0x02,
	MODBUS_DIAG_CHGDELIMITER       = 0x03,
	MODBUS_DIAG_FORCELISTENMODE    = 0x04,
	MODBUS_DIAG_CLEARCOUNTERS      = 0x0a,
	MODBUS_DIAG_GETBUSMSGCOUNT     = 0x0b,
	MODBUS_DIAG_GETBUSERRCOUNT     = 0x0c,
	MODBUS_DIAG_GETSLAVEMSGCOUNT   = 0x0e,
	MODBUS_DIAG_GETSLAVENORSPCOUNT = 0x0f,
	MODBUS_DIAG_GETSLAVENAKCOUNT   = 0x10,
	MODBUS_DIAG_GETSLAVEBUSYCOUNT  = 0x11,
	MODBUS_DIAG_GETBUSOVERRUNCOUNT = 0x12,
	MODBUS_DIAG_CLEAROVERRUNSTATS  = 0x14
} ModbusDiagnosticCode;

typedef enum tagModbusMEICode {
	MODBUS_MEI_ENCAPX         = 0x0d,
	MODBUS_MEI_ENCAPY         = 0x0e,
	MODBUS_MEI_CANOPENREQUEST = 0x0d,
	MODBUS_MEI_READDEVICEINFO = 0x0e
} ModbusMEICode;

typedef struct tagModbusFunctionRange {
	struct {
		iecUSINT start;
		iecUSINT stop;
	} classRange;
	struct {
		iecUINT  start;
		iecUINT  stop;
	} subtypeRange;
	ModbusFunctionClass    class;
	ModbusFunctionSubtype  subtype;
} ModbusFunctionRange;

typedef struct tagModbusHeader {
	iecUINT  transactionId;
	iecUINT  protocolId;
	iecUINT  length;
	iecUSINT unitId;
	ModbusFunction function;
	//
	iecBOOL  hasUnknownFunction;
	iecBOOL  hasErrorResponse;
	ModbusFunctionClass functionClass;
} ModbusHeader;

typedef struct tagModbus {
	ModbusHeader *header;
	ModbusStatus status;
	iecUINT  subcode;
	iecUSINT mei;
	struct {
		iecUINT  dataOffset;
		iecUINT  dataLength;
		iecUSINT *data;
	} request;
	struct {
		iecUINT  dataOffset;
		iecUINT  dataLength;
		iecUSINT *data;
	} response;
	ModbusFunctionSubtype functionSubtype;
} Modbus;

iecDINT          icsInitializeModbus(char *(*configLoader)(char *name));
void             icsUninitializeModbus(void);

IcsParseResult icsParseModbus(IcsLayer startLayer, IcsMode mode,
								  iecBYTE *data, iecUDINT octets,
								  IcsStack *stack);

IcsProtocol    icsProbeModbus(IcsLayer startLayer,
								  iecBYTE *data, iecUDINT octets);

void             icsFreeModbus(void *p);

IcsDetectItem *icsMungeModbus(const char *keyword, const char *options);

#endif
