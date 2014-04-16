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
 * Ethernet/IP Primitives.
 *
 */

#if !defined(_icsenip_h)
#define _icsenip_h

#include "ics.h"
#include "icspredicate.h"
#include "icscip.h"

#define ENIP_HDR_LEN        24
#define ENIP_TRX_TTL        30
#define ENIP_MAXCPF_ITEMS   16

#define ENIP_PREDICATE_FALSE    "0"
#define ENIP_PREDICATE_TRUE     "1"
#define ENIP_PREDICATE_FUNCTION "eip.header.command in sig.commands"
#define ENIP_PREDICATE_STATUS   "eip.header.status in sig.statuses"
#define ENIP_PREDICATE_CPFTYPES "eip.cpf.types in sig.cpftypes"

typedef enum tagEnipCommand {
    ENIP_CMD_NOP               = 0x00,
    ENIP_CMD_LISTSERVICES      = 0x04,
    ENIP_CMD_LISTIDENTITY      = 0x63,
    ENIP_CMD_LISTINTERFACES    = 0x64,
    ENIP_CMD_REGISTERSESSION   = 0x65,
    ENIP_CMD_UNREGISTERSESSION = 0x66,
    ENIP_CMD_SENDRRDATA        = 0x6f,
    ENIP_CMD_SENDUNITDATA      = 0x70,
    ENIP_CMD_INDICATESTATUS    = 0x72,
    ENIP_CMD_CANCEL            = 0x73
} EnipCommand;

typedef enum tagEnipStatusCodes {
    ENIP_STAT_SUCCESS        = 0x0000,
    ENIP_STAT_INVALIDCMD     = 0x0001,
    ENIP_STAT_NORESOURCES    = 0x0002,
    ENIP_STAT_INCORRECTDATA  = 0x0003,
    ENIP_STAT_INVALIDSESSION = 0x0064,
    ENIP_STAT_INVALIDLENGTH  = 0x0065,
    ENIP_STAT_UNSUPPORTEDREV = 0x0069
} EnipStatusCodes;

typedef enum tagEnipItemId {
    ENIP_DATAITEM_NULLADDRESS         = 0x0000,
    ENIP_DATAITEM_LISTIDENTITY        = 0x000c,
    ENIP_DATAITEM_CONNECTEDADDRESS    = 0x00a1,
    ENIP_DATAITEM_CONNECTEDTRANSPORT  = 0x00b1,
    ENIP_DATAITEM_UNCONNECTEDMESSAGE  = 0x00b2,
    ENIP_DATAITEM_LISTSERVICES        = 0x0100,
    ENIP_DATAITEM_O2TSOCKADDRESS      = 0x8000,
    ENIP_DATAITEM_T2OSOCKADDRESS      = 0x8001,
    ENIP_DATAITEM_SEQUENCEDADDRESS    = 0x8002
} EnipItemId;

typedef struct tagEnipSockAddress {
    iecINT   family;
    iecUINT  port;
    iecUDINT address;
    iecUSINT *zero;
} EnipSockAddress;

typedef struct tagEnipHeader {
    EnipCommand command;
    iecUINT  length;
    iecUDINT session;
    iecUDINT status;
    iecBYTE  *context;
    iecUDINT options;
    //
    iecBOOL  hasInvalidCommand;
    iecBOOL  hasInvalidOptions;
} EnipHeader;

typedef struct tagEnipCommandData {
    iecUDINT interface;
    iecUINT  timeout;
    iecUINT  addressType;
    iecUINT  addressLength;
    iecBYTE  *address;
    iecUINT  dataType;
    iecUINT  dataLength;
    iecBYTE  *data;
} EnipCommandData;

typedef struct tagEnipDataItem {
    EnipItemId type;
    iecUINT length;
    iecBYTE *data;
    struct tagEnipDataItem *next;
    //
    iecBYTE  *srcData;
    iecUDINT  srcOctets;
} EnipDataItem;

typedef struct tagEnipCPF {
    uint16_t items;
    EnipDataItem *item;
    iecUINT  errorCount;
    iecUINT  nullAddressCount;
    iecUINT  connectedAddressCount;
    iecUDINT connectedAddressIdentifier;
    iecUINT  o2tSockAddressCount;
    EnipSockAddress o2tSockAddress;
    iecUINT  t2oSockAddressCount;
    EnipSockAddress t2oSockAddress;
    iecUINT  sequencedAddressCount;
    iecUDINT sequencedAddressIdentifier;
    iecUDINT sequencedAddressSequenceNumber;
    iecUINT  listIdentityCount;
    iecUINT  connectedTransportCount;
    iecUINT  connectedTransportSequence;
    iecUINT  unconnectedMessageCount;
    iecUINT  listServicesCount;
} EnipCPF;

typedef struct tagEnipCmdNop {
    iecBYTE *junk;
    //
    iecBOOL statusNotZero;
    iecBOOL optionsNotZero;
} EnipCmdNop;

typedef struct tagEnipCmdListIdentity {
    iecUINT  type;
    iecUINT  length;
    iecUINT  version;
    EnipSockAddress address;
    iecUINT  vendorId;
    iecUINT  deviceType;
    iecUINT  productCode;
    iecUSINT *revision;
    iecWORD  status;
    iecUDINT serial;
    iecSHORTSTRING *name;
    iecUSINT state;
    struct tagEnipCmdListIdentity *next;
} EnipCmdListIdentity;

typedef struct tagEnipCmdListInterfaces {
    iecUINT type;
    iecUINT length;
    EnipCPF *cpf;
    struct tagEnipCmdListInterfaces *next;
} EnipCmdListInterfaces;

typedef struct tagEnipCmdRegisterSession {
    iecUINT version;
    iecUINT flags;
    //
    iecBOOL hasInvalidDataLength;
    iecBOOL hasNonZeroOptions;
} EnipCmdRegisterSession;

typedef struct tagEnipCmdUnregisterSession {
    //
    iecBOOL hasZeroSession;
    iecBOOL hasInvalidDataLength;
    iecBOOL hasNonZeroStatus;
    iecBOOL hasNonZeroOptions;
} EnipCmdUnregisterSession;

typedef struct tagEnipCmdListServices {
    iecUINT  type;
    iecUINT  length;
    iecUINT  version;
    iecUINT  capabilities;
    iecSINT  *name;
    //
    iecBOOL  doesTCP;
    iecBOOL  doesUDP;
    struct tagEnipCmdListServices *next;
} EnipCmdListServices;

typedef struct tagEnipCmdSendRRData {
    iecUDINT interface;
    iecUINT  timeout;
    EnipCPF  *cpf;
    //
    iecBOOL  hasInvalidCip;
    iecBOOL  hasInvalidHeaderLength;
} EnipCmdSendRRData;

typedef struct tagEnipCmdSendUnitData {
    iecUDINT interface;
    iecUINT  timeout;
    EnipCPF  *cpf;
    //
    iecBOOL  hasInvalidCip;
    iecBOOL  hasInvalidHeaderLength;
    iecBOOL  hasNonZeroTimeout;
} EnipCmdSendUnitData;

typedef struct tagEnipCmdIndicateStatus {
    iecBOOL isStatusRequested;
} EnipCmdIndicateStatus;

typedef struct tagEnipCmdCancel {
    iecBOOL isCanceled;
} EnipCmdCancel;

typedef struct tagEnipCmdUnknown {
    iecBYTE *data;
    iecUINT length;
} EnipCmdUnknown;

typedef struct tagEnip {

    EnipHeader *header;
    EnipCPF    *cpf;

    EnipCmdNop               *nop;
    EnipCmdListIdentity      *listIdentity;
    EnipCmdListServices      *listServices;
    EnipCmdListInterfaces    *listInterfaces;
    EnipCmdRegisterSession   *registerSession;
    EnipCmdUnregisterSession *unregisterSession;
    EnipCmdSendRRData        *sendRRData;
    EnipCmdSendUnitData      *sendUnitData;
    EnipCmdIndicateStatus    *indicateStatus;
    EnipCmdCancel            *cancel;
    EnipCmdUnknown           *unknown;

} Enip;

int              icsInitializeEnip(char *(*configLoader)(char *name));
void             icsUninitializeEnip(void);
void             icsFreeEnip(IcsOpaque *p);

IcsDetectItem *icsMungeEnip(const iecSINT *keyword, const iecSINT *options);

IcsParseResult icsParseEnip(IcsLayer startLayer, IcsMode mode,
                                iecBYTE *data, iecUDINT octets,
                                IcsStack *stack);

IcsProtocol    icsProbeEnip(IcsLayer startLayer,
                                iecBYTE *data, iecUDINT octets);

#endif
