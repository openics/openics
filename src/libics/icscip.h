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
 * CIP Primitives.
 *
 */

#if !defined(_icscip_h)
#define _icscip_h

#include "ics.h"
#include "icspredicate.h"

#define CIP_HDR_LEN 	3

#define CIP_PREDICATE_FALSE      "0"
#define CIP_PREDICATE_TRUE       "1"
#define CIP_PREDICATE_FUNCTION   "cip.header.service in sig.services"
#define CIP_PREDICATE_CLASSID	 "cip.request.path.logical.classId == sig.classid"
#define CIP_PREDICATE_ATTRID     "cip.request.path.logical.attributeId == sig.attrid"
#define CIP_PREDICATE_INSTID     "cip.request.path.logical.instanceId == sig.instid"
#define CIP_PREDICATE_STATUS     "cip.response.status in sig.statuses"

typedef enum tagCipService {
	CIP_SRV_GETATTRALL   = 0x01,
	CIP_SRV_SETATTRALL   = 0x02,
	CIP_SRV_GETATTRLIST  = 0x03,
	CIP_SRV_SETATTRLIST  = 0x04,
	CIP_SRV_RESET        = 0x05,
	CIP_SRV_START        = 0x06,
	CIP_SRV_STOP         = 0x07,
	CIP_SRV_CREATE       = 0x08,
	CIP_SRV_DELETE	     = 0x09,
	CIP_SRV_MSP          = 0x0a,
	CIP_SRV_APPLYATTR    = 0x0d,
	CIP_SRV_GETATTR      = 0x0e,
	CIP_SRV_SETATTR      = 0x10,
	CIP_SRV_FINDNEXTOBJ  = 0x11,
	CIP_SRV_RESTORE      = 0x15,
	CIP_SRV_SAVE         = 0x16,
	CIP_SRV_NOOP         = 0x17,
	CIP_SRV_GETMEMBER    = 0x18,
	CIP_SRV_SETMEMBER    = 0x19,
	CIP_SRV_INSERTMEMBER = 0x1a,
	CIP_SRV_REMOVEMEMBER = 0x1b,
	CIP_SRV_GROUPSYNC    = 0x1c,
	CIP_SRV_KICKTIMER    = 0x4b,
	CIP_SRV_OPENCONN     = 0x4c,
	CIP_SRV_CLOSECONN    = 0x4d,
	CIP_SRV_STOPCONN     = 0x4e,
	CIP_SRV_CHANGESTART  = 0x4f,
	CIP_SRV_GETSTATUS    = 0x50,
	CIP_SRV_CHANGEDONE   = 0x51,
	CIP_SRV_AUDITCHANGE  = 0x52,
	CIP_SRV_FWDOPEN      = 0x54,
	CIP_SRV_LARGEFWDOPEN = 0x5b,
	CIP_SRV_GETCONNOWNER = 0x5a,
	CIP_SRV_MASK         = 0x7f,
	CIP_SRV_RESPONSEMASK = 0x80
} CipService;

typedef enum tagCipStat {
	CIP_STAT_SUCCESS           = 0x00,
	CIP_STAT_FAILURE           = 0x01,
	CIP_STAT_NORESOURCE        = 0x02,
	CIP_STAT_BADDATA           = 0x03,
	CIP_STAT_BADPATH           = 0x04,
	CIP_STAT_BADCLASSINST      = 0x05,
	CIP_STAT_PARTIALDATA       = 0x06,
	CIP_STAT_CONNLOST          = 0x07,
	CIP_STAT_BADSERVICE        = 0x08,
	CIP_STAT_BADATTRDATA       = 0x09,
	CIP_STAT_ATTRLISTERROR     = 0x0a,
	CIP_STAT_ALREADYINMODE     = 0x0b,
	CIP_STAT_BADOBJMODE        = 0x0c,
	CIP_STAT_OBJEXISTS         = 0x0d,
	CIP_STAT_ATTRNOTSETTABLE   = 0x0e,
	CIP_STAT_PERMISSIONDENIED  = 0x0f,
	CIP_STAT_DEVINWRONGSTATE   = 0x10,
	CIP_STAT_REPLYTOOLARGE     = 0x11,
	CIP_STAT_FRAGPRIMITIVE     = 0x12,
	CIP_STAT_CONFIGTOOSMALL    = 0x13,
	CIP_STAT_UNDEFINEDATTR     = 0x14,
	CIP_STAT_CONFIGTOOBIG	   = 0x15,
	CIP_STAT_OBJDOESNOTEXIST   = 0x16,
	CIP_STAT_NOFRAG			   = 0x17,
	CIP_STAT_DATANOTSAVED      = 0x18,
	CIP_STAT_DATAWRITEFAILURE  = 0x19,
	CIP_STAT_REQUESTTOOLARGE   = 0x1a,
	CIP_STAT_RESPONSETOOLARGE  = 0x1b,
	CIP_STAT_MISSINGLISTDATA   = 0x1c,
	CIP_STAT_INVALIDLISTSTATUS = 0x1d,
	CIP_STAT_SERVICEERROR      = 0x1e,
	CIP_STAT_CONNFAILURE       = 0x1f,
	CIP_STAT_INVALIDPARAMETER  = 0x20,
	CIP_STAT_WRITEONCEFAILURE  = 0x21,
	CIP_STAT_INVALIDREPLY      = 0x22,
	CIP_STAT_BUFFEROVERFLOW    = 0x23,
	CIP_STAT_MESSAGEFORMAT     = 0x24,
	CIP_STAT_BADKEYINPATH      = 0x25,
	CIP_STAT_BADPATHSIZE       = 0x26,
	CIP_STAT_UNEXPECTEDATTR    = 0x27,
	CIP_STAT_INVALIDMEMBER     = 0x28,
	CIP_STAT_MEMBERNOTSETTABLE = 0x29,
	CIP_STAT_G2SERVERFAILURE   = 0x2a,
	CIP_STAT_UNKNOWNMBERROR    = 0x2b,
	CIP_STAT_STILLPROCESSING   = 0xff
} CipStat;

typedef enum tagCipObjectID {
	CIP_OID_IDENTITY            = 0x01,
	CIP_OID_MSGROUTER		    = 0x02,
	CIP_OID_DEVICENET		    = 0x03,
	CIP_OID_ASSEMBLY		    = 0x04,
	CIP_OID_CONNECTION		    = 0x05,
	CIP_OID_CONNMANAGER		    = 0x06,
	CIP_OID_REGISTER		    = 0x07,
	CIP_OID_DISCINPPOINT		= 0x08,
	CIP_OID_DISCOUTPOINT		= 0x09,
	CIP_OID_ANAINPPOINT		    = 0x0a,
	CIP_OID_ANAOUTPOINT		    = 0x0b,
	CIP_OID_PRESSENSING		    = 0x0e,
	CIP_OID_PARAMETER		    = 0x0f,
	CIP_OID_PARMGROUP		    = 0x10,
	CIP_OID_GROUP		        = 0x12,
	CIP_OID_DISCINPGROUP		= 0x1d,
	CIP_OID_DISCOUTGROUP		= 0x1e,
	CIP_OID_DISCGROUP		    = 0x1f,
	CIP_OID_ANAINPGROUP		    = 0x20,
	CIP_OID_ANAOUTGROUP		    = 0x21,
	CIP_OID_ANAGROUP		    = 0x22,
	CIP_OID_POSSENSOR		    = 0x23,
	CIP_OID_POSCONTSUPER		= 0x24,
	CIP_OID_POSCONTROLLER		= 0x25,
	CIP_OID_BLOCKSEQENCER		= 0x26,
	CIP_OID_COMMANDBLOCK		= 0x27,
	CIP_OID_MOTORDATA		    = 0x28,
	CIP_OID_CONTSUPER		    = 0x29,
	CIP_OID_ACDCDRIVE		    = 0x2a,
	CIP_OID_ACKHANDLER		    = 0x2b,
	CIP_OID_OVERLOAD		    = 0x2c,
	CIP_OID_SOFTSTART		    = 0x2d,
	CIP_OID_SELECTION		    = 0x2e,
	CIP_OID_DEVICESUPER		    = 0x30,
	CIP_OID_SANASENSOR		    = 0x31,
	CIP_OID_SANAACTUATOR		= 0x32,
	CIP_OID_SSINGLESTAGECONT	= 0x33,
	CIP_OID_SGASCALIBRATION		= 0x34,
	CIP_OID_TRIPPOINT		    = 0x35,
	CIP_OID_DRIVEDATA		    = 0x36, // n/a?
	CIP_OID_FILE		        = 0x37,
	CIP_OID_SPARTPRESSURE		= 0x38,
	CIP_OID_SAFESUPER	        = 0x39,
	CIP_OID_SAFEVALIDATOR		= 0x3a,
	CIP_OID_SAFEDISCOUTPOINT	= 0x3b,
	CIP_OID_SAFEDISCOUTGROUP	= 0x3c,
	CIP_OID_SAFEDISCINPPOINT	= 0x3d,
	CIP_OID_SAFEDISCINPGROUP	= 0x3e,
	CIP_OID_SAFEDUALCHANOUTPUT	= 0x3f,
	CIP_OID_SSENSORCALIBRATION	= 0x40,
	CIP_OID_EVENTLOG		    = 0x41,
	CIP_OID_MOTIONAXIS		    = 0x42,
	CIP_OID_TIMESYNC		    = 0x43,
	CIP_OID_MODBUS		        = 0x44,
	CIP_OID_CONTNET		        = 0xf0,
	CIP_OID_CONTNETKEEPER		= 0xf1,
	CIP_OID_CONTNETSCHED		= 0xf2,
	CIP_OID_CONNCONFIG		    = 0xf3,
	CIP_OID_PORT		        = 0xf4,
	CIP_OID_TCPIPXFACE		    = 0xf5,
	CIP_OID_ETHERLINK		    = 0xf6,
	CIP_OID_COMPONETLINK		= 0xf7,
	CIP_OID_COMPONETREPEATER	= 0xf8
} CipObjectId;

typedef enum tagCipSegmentType {
	CIP_SEGT_PORT     = 0x00,
	CIP_SEGT_LOGICAL  = 0x20,
	CIP_SEGT_NETWORK  = 0x40,
	CIP_SEGT_SYMBOLIC = 0x60,
	CIP_SEGT_DATA     = 0x80,
	CIP_SEGT_CTYPE    = 0xa0,
	CIP_SEGT_ETYPE    = 0xc0,
	CIP_SEGT_MASK     = 0xe0
} CipSegmentType;

typedef enum tagCipSegmentLogicalType {
	CIP_SEGLT_CLASSID   = 0x00,
	CIP_SEGLT_INSTID    = 0x04,
	CIP_SEGLT_MEMBERID  = 0x08,
	CIP_SEGLT_CONNPOINT = 0x0c,
	CIP_SEGLT_ATTRID    = 0x10,
	CIP_SEGLT_SPECIAL   = 0x14,
	CIP_SEGLT_SERVICEID = 0x18,
	CIP_SEGLT_MASK      = 0x1c
} CipSegmentLogicalType;

typedef enum tagCipSegmentLogicalFormat {
	CIP_SEGLF_8BIT  = 0x00,
	CIP_SEGLF_16BIT = 0x01,
	CIP_SEGLF_32BIT = 0x02,
	CIP_SEGLF_MASK  = 0x03,
	CIP_SEGLF_SRVID = 0x00,
	CIP_SEGLF_EKEY  = 0x00
} CipSegmentLogicalFormat;

typedef enum tagCipSegmentNetworkType {
	CIP_SEGNT_SCHEDULE  = 0x01,
	CIP_SEGNT_FIXEDTAG  = 0x02,
	CIP_SEGNT_PRODINHIB = 0x03,
	CIP_SEGNT_SAFETY    = 0x10,
	CIP_SEGNT_EXTENDED  = 0x1f,
	CIP_SEGNT_MASK      = 0x1f
} CipSegmentNetworkType;

typedef enum tagCipSegmentXStringType {
	CIP_SEGXS_DOUBLES = 0x20,
	CIP_SEGXS_TRIPLES = 0x40,
	CIP_SEGXS_NUMERIC = 0xc0,
	CIP_SEGXS_MASK    = 0xe0
} CipSegmentXStringType;

typedef enum tagCipSegmentXStringNType {
	CIP_SEGXST_BYTE  = 0x06,
	CIP_SEGXST_WORD  = 0x07,
	CIP_SEGXST_DWORD = 0x08,
	CIP_SEGXST_MASK  = 0x1f
} CipSegmentXStringNType;

typedef enum tagCipSegmentDataType {
	CIP_SEGDT_SIMPLE = 0x00,
	CIP_SEGDT_ANSIX  = 0x11,
	CIP_SEGDT_MASK   = 0x1f
} CipSegmentDataType;

typedef enum tagCipSegmentOption {
	CIP_SEGO_PORTBIGADDR = 0x10,
	CIP_SEGO_PORTIDMASK  = 0x0f,
	CIP_SEGO_SYMSIZEMASK = 0x1f
} CipSegmentOption;

typedef struct tagCipPortSegment {
	iecUINT  portId;
	iecUSINT linkAddressSize;
	iecUSINT *linkAddress;
} CipPortSegment;

typedef struct tagCipElectronicKey {
	iecUINT  vendorId;
	iecUINT  deviceType;
	iecUINT  productCode;
	iecBYTE  majorRev;
	iecUSINT minorRev;
	iecBOOL  isCompatible;
} CipElectronicKey;

typedef struct tagCipLogicalSegment {
	CipSegmentLogicalType type;
	CipSegmentLogicalFormat format;
	iecUSINT padByte;
	iecUDINT value;
	iecUSINT serviceId;
	CipElectronicKey *ekey;
} CipLogicalSegment;

typedef struct tagCipNetworkSegment {
	CipSegmentNetworkType type;
	iecUSINT inhibitTime;
	iecUSINT length;
	iecWORD  extendedSubType;
	iecWORD  *extendedData;
	iecBOOL  isUnknownType;
} CipNetworkSegment;

typedef struct tagCipSymbolicSegment {
	iecUSINT   padByte;
	iecUSINT   length;
	iecSTRING  *asciiString;
	iecSTRING2 *doubleString;
	iecSTRING3 *tripleString;
	iecUDINT   numericSymbol;
	iecBOOL    isNumeric;
	iecBOOL    isUnknownXFormat;
	iecBOOL    isUnknownXType;
} CipSymbolicSegment;

typedef struct tagCipDataSegment {
	CipSegmentDataType type;
	iecUSINT  length;
	iecBYTE  *ansiData;
	iecWORD  *simpleData;
} CipDataSegment;

typedef struct tagCTypeSegment {
	iecBOOL notImplemented;
} CipCTypeSegment;

typedef struct tagETypeSegment {
	iecBOOL notImplemented;
} CipETypeSegment;

typedef struct tagCipSegment {
	CipSegmentType type;
	IcsOpaque *opaque;
	struct tagCipSegment *next;
} CipSegment;

typedef struct tagCipStatus {
	iecBYTE  reserved;
	CipStat  status;
	iecUSINT addlLength;
	iecWORD  *addlStatus;
} CipStatus;

typedef struct tagCipData {
	iecUINT length;
	iecBYTE *data;
	struct tagCipData *next;
} CipData;

typedef struct tagCipHeader {
	CipService service;
	iecBOOL isMsp;
	iecBOOL isRequest;
	iecBOOL isResponse;
	iecBOOL isUnknownService;
} CipHeader;

typedef struct tagCip {
	CipHeader  *header;
	CipSegment *rqPath;
	CipData    *rqData;
	CipStatus  *rsStatus;
	CipData    *rsData;
} Cip;

iecDINT          icsInitializeCip(char *(*configLoader)(char *name));
void             icsUninitializeCip(void);
void 			 icsFreeCip(IcsOpaque *p);

IcsDetectItem *icsMungeCip(const iecSINT *keyword, const iecSINT *options);

IcsParseResult icsParseCip(IcsLayer startLayer, IcsMode mode,
							   iecBYTE *data, iecUDINT octets,
							   IcsStack *stack);

IcsProtocol    icsProbeCip(IcsLayer startLayer,
							   iecBYTE *data, iecUDINT octets);

#endif
