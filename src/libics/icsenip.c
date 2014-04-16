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
 * ENIP Primitives.
 *
 */

/*
enip_func
enip_stat
enip_iface
enip_type
cip_service
cip_path - later
cip_response
cip_data
*/

#include "icsenip.h"

static IcsNumericAssociation enipCommands[] = {
    { ENIP_CMD_NOP,               "nop" },
    { ENIP_CMD_LISTSERVICES,      "list_services" },
    { ENIP_CMD_LISTIDENTITY,      "list_identity" },
    { ENIP_CMD_LISTINTERFACES,    "list_interfaces" },
    { ENIP_CMD_REGISTERSESSION,   "register_session" },
    { ENIP_CMD_UNREGISTERSESSION, "unregister_session" },
    { ENIP_CMD_SENDRRDATA,        "send_rr_data" },
    { ENIP_CMD_SENDUNITDATA,      "send_unit_data" },
    { ENIP_CMD_INDICATESTATUS,    "indicate_status" },
    { ENIP_CMD_CANCEL,            "cancel" },
    { 0x00, NULL }
};

static IcsNumericAssociation enipStatusCodes[] = {
    { ENIP_STAT_SUCCESS,        "success" },
    { ENIP_STAT_INVALIDCMD,     "invalid_command" },
    { ENIP_STAT_NORESOURCES,    "out_of_memory" },
    { ENIP_STAT_INCORRECTDATA,  "incorrect_data" },
    { ENIP_STAT_INVALIDSESSION, "invalid_session" },
    { ENIP_STAT_INVALIDLENGTH,  "invalid_length" },
    { ENIP_STAT_UNSUPPORTEDREV, "unsupported_revision" },
    { 0x00, NULL }
};

static IcsNumericAssociation enipItemIds[] = {
    { ENIP_DATAITEM_NULLADDRESS,        "null_address" },
    { ENIP_DATAITEM_LISTIDENTITY,       "list_identity" },
    { ENIP_DATAITEM_CONNECTEDADDRESS,   "connected_address" },
    { ENIP_DATAITEM_CONNECTEDTRANSPORT, "connected_transport" },
    { ENIP_DATAITEM_UNCONNECTEDMESSAGE, "unconnected_message" },
    { ENIP_DATAITEM_LISTSERVICES,       "list_services" },
    { ENIP_DATAITEM_O2TSOCKADDRESS,     "o2t_socket_address" },
    { ENIP_DATAITEM_T2OSOCKADDRESS,     "t2o_socket_address" },
    { ENIP_DATAITEM_SEQUENCEDADDRESS,   "sequenced_address" },
    { 0x00, NULL }
};

static iecUDINT *avoidFuncs   = NULL;
static iecUINT avoidFuncCount = 0;
static int avoidFunc(iecUINT func)
{
    if(avoidFuncCount > 0 && avoidFuncs != NULL)
        for(iecUINT i = 0; i < avoidFuncCount; i++)
            if(avoidFuncs[i] == func)
                return 1;
    return 0;
}

static char *reverseLookupCommand(uint8_t code)
{
    int i;
    for(i=0; enipCommands[i].name; i++)
        if(enipCommands[i].value == code)
            return enipCommands[i].name;
    return NULL;
}

static IcsOpaque *alloc(void)
{
    ICS_TMEMORY(enip, Enip);
    return enip;
}

static void shoveVariables(IcsTransaction *transaction)
{
    if(transaction != NULL) {
        if(transaction->variables != NULL)
            icsFreePredicateHash(transaction->variables);
        Enip *enip;
        if((enip = transaction->opaque) != NULL) {
            if((transaction->variables = icsHashCreate(16, 90, SCHA_DEFAULT)) != NULL) {

                ICS_SHOVENUMBER("eip.header.command",        enip->header->command);
                ICS_SHOVENUMBER("eip.header.invalidCommand", enip->header->hasInvalidCommand);
                ICS_SHOVENUMBER("eip.header.invalidOptions", enip->header->hasInvalidOptions);
                ICS_SHOVENUMBER("eip.header.options",        enip->header->options);
                ICS_SHOVENUMBER("eip.header.session",        enip->header->session);
                ICS_SHOVENUMBER("eip.header.status",         enip->header->status);

                if(enip->cpf != NULL) {
                    ICS_SHOVEARRAY("eip.cpf.types", enip->cpf->item, type, next);

                    if(enip->cpf->connectedAddressCount > 0) {
                        ICS_SHOVENUMBER("eip.cpf.hasConnectedAddress", 1);
                        ICS_SHOVENUMBER("eip.cpf.connectedAddressId",  enip->cpf->connectedAddressIdentifier);
                    }
                    if(enip->cpf->connectedTransportCount > 0) {
                        ICS_SHOVENUMBER("eip.cpf.hasConnectedTransport", 1);
                        ICS_SHOVENUMBER("eip.cpf.connectedTransportSeq", enip->cpf->connectedTransportSequence);
                    }
                    if(enip->cpf->listIdentityCount > 0) {
                        ICS_SHOVENUMBER("eip.cpf.hasListIdentity", 1);
                    }
                    if(enip->cpf->listServicesCount > 0) {
                        ICS_SHOVENUMBER("eip.cpf.hasListServices", 1);
                    }
                    if(enip->cpf->nullAddressCount > 0) {
                        ICS_SHOVENUMBER("eip.cpf.hasNullAddress", 1);
                    }
                    if(enip->cpf->o2tSockAddressCount > 0) {
                        ICS_SHOVENUMBER("eip.cpf.haso2tSockAddress",   1);
                        ICS_SHOVENUMBER("eip.cpf.o2tSockAddr.address", enip->cpf->o2tSockAddress.address);
                        ICS_SHOVENUMBER("eip.cpf.o2tSockAddr.family",  enip->cpf->o2tSockAddress.family);
                        ICS_SHOVENUMBER("eip.cpf.o2tSockAddr.port",    enip->cpf->o2tSockAddress.port);
                    }
                    if(enip->cpf->t2oSockAddressCount > 0) {
                        ICS_SHOVENUMBER("eip.cpf.hast2oSockAddress",   1);
                        ICS_SHOVENUMBER("eip.cpf.t2oSockAddr.address", enip->cpf->o2tSockAddress.address);
                        ICS_SHOVENUMBER("eip.cpf.t2oSockAddr.family",  enip->cpf->o2tSockAddress.family);
                        ICS_SHOVENUMBER("eip.cpf.t2oSockAddr.port",    enip->cpf->o2tSockAddress.port);
                    }
                    if(enip->cpf->sequencedAddressCount > 0) {
                        ICS_SHOVENUMBER("eip.cpf.hasSequencedAddress",   1);
                        ICS_SHOVENUMBER("eip.cpf.sequencedAddressId",    enip->cpf->sequencedAddressIdentifier);
                        ICS_SHOVENUMBER("eip.cpf.sequencedAddressSeqNo", enip->cpf->sequencedAddressSequenceNumber);
                    }
                    if(enip->cpf->unconnectedMessageCount > 0) {
                        ICS_SHOVENUMBER("eip.cpf.hasUnconnectedMessage", 1);
                    }
                }
                if(enip->nop != NULL) {
                    ICS_SHOVENUMBER("eip.header.hasNop", 1);
                }
                if(enip->listServices != NULL) {
                    ICS_SHOVENUMBER("eip.header.hasListServices", 1);
                    ICS_SHOVENUMBER("eip.command.listServices.capabilities", enip->listServices->capabilities);
                    ICS_SHOVENUMBER("eip.command.listServices.doesTCP",      enip->listServices->doesTCP);
                    ICS_SHOVENUMBER("eip.command.listServices.doesUDP",      enip->listServices->doesUDP);
                    ICS_SHOVESTRING("eip.command.listServices.name",         enip->listServices->name);
                    ICS_SHOVENUMBER("eip.command.listServices.type",         enip->listServices->type);
                    ICS_SHOVENUMBER("eip.command.listServices.version",      enip->listServices->version);
                }
                if(enip->listIdentity != NULL) {
                    ICS_SHOVENUMBER("eip.header.hasListIdentity", 1);
                    ICS_SHOVENUMBER("eip.command.listIdentity.sockAddr.address", enip->listIdentity->address.address);
                    ICS_SHOVENUMBER("eip.command.listIdentity.sockAddr.family",  enip->listIdentity->address.family);
                    ICS_SHOVENUMBER("eip.command.listIdentity.sockAddr.port",    enip->listIdentity->address.port);
                    ICS_SHOVENUMBER("eip.command.listIdentity.deviceType",       enip->listIdentity->deviceType);
                    ICS_SHOVESTRING("eip.command.listIdentity.name",             enip->listIdentity->name->string);
                    ICS_SHOVENUMBER("eip.command.listIdentity.productCode",      enip->listIdentity->productCode);
                    ICS_SHOVENUMBER("eip.command.listIdentity.revisionA",        enip->listIdentity->revision[0]);
                    ICS_SHOVENUMBER("eip.command.listIdentity.revisionB",        enip->listIdentity->revision[1]);
                    ICS_SHOVENUMBER("eip.command.listIdentity.serial",           enip->listIdentity->serial);
                    ICS_SHOVENUMBER("eip.command.listIdentity.state",            enip->listIdentity->state);
                    ICS_SHOVENUMBER("eip.command.listIdentity.status",           enip->listIdentity->status);
                    ICS_SHOVENUMBER("eip.command.listIdentity.type",             enip->listIdentity->type);
                    ICS_SHOVENUMBER("eip.command.listIdentity.vendorId",         enip->listIdentity->vendorId);
                }
                if(enip->listInterfaces != NULL) {
                    ICS_SHOVENUMBER("eip.header.hasListInterfaces", 1);
                    ICS_SHOVENUMBER("eip.command.listInterfaces.type", enip->listInterfaces->type);
                }
                if(enip->registerSession != NULL) {
                    ICS_SHOVENUMBER("eip.header.hasRegisterSession", 1);
                    ICS_SHOVENUMBER("eip.command.registerSession.flags",                enip->registerSession->flags);
                    ICS_SHOVENUMBER("eip.command.registerSession.hasInvalidDataLength", enip->registerSession->hasInvalidDataLength);
                    ICS_SHOVENUMBER("eip.command.registerSession.hasNonZeroOptions",    enip->registerSession->hasNonZeroOptions);
                    ICS_SHOVENUMBER("eip.command.registerSession.version",              enip->registerSession->version);
                }
                if(enip->unregisterSession != NULL) {
                    ICS_SHOVENUMBER("eip.header.hasUnregisterSession", 1);
                    ICS_SHOVENUMBER("eip.command.unregisterSession.hasInvalidDataLength", enip->unregisterSession->hasInvalidDataLength);
                    ICS_SHOVENUMBER("eip.command.unregisterSession.hasNonZeroOptions",    enip->unregisterSession->hasNonZeroOptions);
                    ICS_SHOVENUMBER("eip.command.unregisterSession.hasNonZeroStatus",     enip->unregisterSession->hasNonZeroStatus);
                    ICS_SHOVENUMBER("eip.command.unregisterSession.hasZeroSession",       enip->unregisterSession->hasZeroSession);
                }
                if(enip->sendRRData != NULL) {
                    ICS_SHOVENUMBER("eip.header.hasSendRRData", 1);
                    ICS_SHOVENUMBER("eip.command.sendRRData.hasInvalidCip",          enip->sendRRData->hasInvalidCip);
                    ICS_SHOVENUMBER("eip.command.sendRRData.hasInvalidHeaderLength", enip->sendRRData->hasInvalidHeaderLength);
                    ICS_SHOVENUMBER("eip.command.sendRRData.interface",              enip->sendRRData->interface);
                    ICS_SHOVENUMBER("eip.command.sendRRData.timeout",                enip->sendRRData->timeout);
                }
                if(enip->sendUnitData != NULL) {
                    ICS_SHOVENUMBER("eip.header.hasSendUnitData", 1);
                    ICS_SHOVENUMBER("eip.command.sendUnitData.hasInvalidCip",          enip->sendUnitData->hasInvalidCip);
                    ICS_SHOVENUMBER("eip.command.sendUnitData.hasInvalidHeaderLength", enip->sendUnitData->hasInvalidHeaderLength);
                    ICS_SHOVENUMBER("eip.command.sendUnitData.hasNonZeroTimeout",      enip->sendUnitData->hasNonZeroTimeout);
                    ICS_SHOVENUMBER("eip.command.sendUnitData.interface",              enip->sendUnitData->interface);
                    ICS_SHOVENUMBER("eip.command.sendUnitData.timeout",                enip->sendUnitData->timeout);
                }
                if(enip->indicateStatus != NULL) {
                    ICS_SHOVENUMBER("eip.header.hasIndicateStatus", 1);
                    ICS_SHOVENUMBER("eip.command.indicateStatus.isStatusRequested", enip->indicateStatus->isStatusRequested);
                }
                if(enip->cancel != NULL) {
                    ICS_SHOVENUMBER("eip.header.hasCancel", 1);
                    ICS_SHOVENUMBER("eip.command.cancel.isCanceled", enip->cancel->isCanceled);
                }
                if(enip->unknown != NULL) {
                    ICS_SHOVENUMBER("eip.header.hasUnknown", 1);
                    ICS_SHOVENUMBER("eip.command.unknown.length", enip->unknown->length);
                }
            }
        }
    }
}

static IcsParseResult parseCPF(EnipCPF **cpf, iecBYTE *data, iecUDINT octets, int *po)
{
    int o = *po;
    ICS_TMEMORY_P(current, EnipCPF);
    *cpf = current;
    ICS_UINT(current->items);
    if(current->items > ENIP_MAXCPF_ITEMS) {
        icsSaveHex(data, octets, octets, ICS_HEXDUMP_QUOTED, "ENIP - exceeded maximum cpf (max:%u, has:%u), ", ENIP_MAXCPF_ITEMS, current->items);
        return ICS_RESULT_LIMITEXCEEDED;
    }
    iecUINT ui;
    EnipDataItem *item = NULL;
    for(ui=0; ui < current->items; ui++) {
        if(current->item == NULL) {
            ICS_TMEMORY_P(newItem, EnipDataItem);
            current->item = item = newItem;
        }
        else
        if(item != NULL) {
            ICS_TMEMORY_P(newItem, EnipDataItem);
            item = item->next = newItem;
        }
        ICS_UINT(item->type);
        ICS_UINT(item->length);
        ICS_BYTES(item->data, item->length);
        item->srcData = data;
        item->srcOctets = octets;
    }
    icsSaveHex(data, octets, octets, ICS_HEXDUMP_QUOTED, "ENIP - common packet format, ");
    *po = o;
    return ICS_RESULT_OK;
}

static IcsParseResult parseCPFRound2(EnipCPF *cpf, IcsStack *stack)
{
    IcsParseResult r = ICS_RESULT_OK;
    EnipDataItem *item = cpf->item;
    if(item == NULL)
        return ICS_RESULT_OK;
    for(item = cpf->item; item != NULL; item = item->next) {
        int o = 0;
        iecBYTE *data  = item->data;
        iecUDINT octets = item->length;
        switch(item->type) {
            case ENIP_DATAITEM_NULLADDRESS:
            icsSaveHex(item->srcData, item->srcOctets, item->srcOctets, ICS_HEXDUMP_QUOTED, "ENIP - common packet format 'NullAddress', ");
            if(item->length == 0)
                cpf->nullAddressCount++;
            else
                cpf->errorCount++;
            break;

            case ENIP_DATAITEM_LISTIDENTITY:
            icsSaveHex(item->srcData, item->srcOctets, item->srcOctets, ICS_HEXDUMP_QUOTED, "ENIP - common packet format 'ListIdentity', ");
            if(item->length > 0) {
                cpf->listIdentityCount++;
                r = icsParseCip(ICS_LAYER_APPLICATION | ICS_LAYER_ENCAP | ICS_PROTO_ENIP, ICS_MODE_UNK, data, octets, stack);
            } else
                cpf->errorCount++;
            break;

            case ENIP_DATAITEM_CONNECTEDADDRESS:
            icsSaveHex(item->srcData, item->srcOctets, item->srcOctets, ICS_HEXDUMP_QUOTED, "ENIP - common packet format 'ConnectedAddress', ");
            if(item->length == 4) {
                cpf->connectedAddressCount++;
                ICS_UDINT(cpf->connectedAddressIdentifier);
            } else
                cpf->errorCount++;
            break;

            case ENIP_DATAITEM_CONNECTEDTRANSPORT:
            icsSaveHex(item->srcData, item->srcOctets, item->srcOctets, ICS_HEXDUMP_QUOTED, "ENIP - common packet format 'ConnectedTransport', ");
            if(item->length > 0) {
                cpf->connectedTransportCount++;
                ICS_UINT(cpf->connectedTransportSequence);
                r = icsParseCip(ICS_LAYER_APPLICATION | ICS_LAYER_ENCAP | ICS_PROTO_ENIP, ICS_MODE_UNK, data+o, octets-o, stack);
            } else
                cpf->errorCount++;
            break;

            case ENIP_DATAITEM_UNCONNECTEDMESSAGE:
            icsSaveHex(item->srcData, item->srcOctets, item->srcOctets, ICS_HEXDUMP_QUOTED, "ENIP - common packet format 'UnconnectedMessage', ");
            if(item->length > 0) {
                cpf->unconnectedMessageCount++;
                r = icsParseCip(ICS_LAYER_APPLICATION | ICS_LAYER_ENCAP | ICS_PROTO_ENIP, ICS_MODE_UNK, data, octets, stack);
            } else
                cpf->errorCount++;
            break;

            case ENIP_DATAITEM_LISTSERVICES:
            icsSaveHex(item->srcData, item->srcOctets, item->srcOctets, ICS_HEXDUMP_QUOTED, "ENIP - common packet format 'ListServices', ");
            if(item->length > 0) {
                cpf->listServicesCount++;
                r = icsParseCip(ICS_LAYER_APPLICATION | ICS_LAYER_ENCAP | ICS_PROTO_ENIP, ICS_MODE_UNK, data, octets, stack);
            } else
                cpf->errorCount++;
            break;

            case ENIP_DATAITEM_O2TSOCKADDRESS:
            icsSaveHex(item->srcData, item->srcOctets, item->srcOctets, ICS_HEXDUMP_QUOTED, "ENIP - common packet format 'O2TAddress', ");
            if(item->length == 16) {
                cpf->o2tSockAddressCount++;
                ICS_INT_BE(cpf->o2tSockAddress.family);
                ICS_UINT_BE(cpf->o2tSockAddress.port);
                ICS_UDINT_BE(cpf->o2tSockAddress.address);
                ICS_USINTS(cpf->o2tSockAddress.zero, 8);
            }
            break;

            case ENIP_DATAITEM_T2OSOCKADDRESS:
            icsSaveHex(item->srcData, item->srcOctets, item->srcOctets, ICS_HEXDUMP_QUOTED, "ENIP - common packet format 'T2OAddress', ");
            if(item->length == 16) {
                cpf->t2oSockAddressCount++;
                ICS_INT_BE(cpf->t2oSockAddress.family);
                ICS_UINT_BE(cpf->t2oSockAddress.port);
                ICS_UDINT_BE(cpf->t2oSockAddress.address);
                ICS_USINTS(cpf->t2oSockAddress.zero, 8);
            }
            break;

            case ENIP_DATAITEM_SEQUENCEDADDRESS:
            icsSaveHex(item->srcData, item->srcOctets, item->srcOctets, ICS_HEXDUMP_QUOTED, "ENIP - common packet format 'SequencedAddress', ");
            if(item->length == 8) {
                cpf->sequencedAddressCount++;
                ICS_UDINT(cpf->sequencedAddressIdentifier);
                ICS_UDINT(cpf->sequencedAddressSequenceNumber);
            } else
                cpf->errorCount++;
            break;

            default:
            icsSaveHex(item->srcData, item->srcOctets, item->srcOctets, ICS_HEXDUMP_QUOTED, "ENIP - common packet format 'Unknown', ");
            r = ICS_RESULT_UNKNOWNITEM;
            break;
        }
    }
    return r;
}

static IcsParseResult parseHeader(EnipHeader **header, iecBYTE *data, iecUDINT octets, int *po)
{
    int o = *po;
    ICS_TMEMORY_P(current, EnipHeader);
    *header = current;
    ICS_UINT(current->command);
    if(avoidFunc(current->command))
        return ICS_RESULT_FUNCTIONIGNORED;
    if(reverseLookupCommand(current->command) == NULL)
        current->hasInvalidCommand = 1;
    ICS_UINT(current->length);
    ICS_UDINT(current->session);
    ICS_UDINT(current->status);
    ICS_BYTES(current->context, 8);
    ICS_UDINT(current->options);
    if(current->options != 0) {
        icsSaveHex(data, octets, octets, ICS_HEXDUMP_QUOTED, "ENIP - invalid header options (0x%04x), ", current->options);
        current->hasInvalidOptions = 1;
    }
    *po = o;
    icsSaveHex(data, octets, octets, ICS_HEXDUMP_QUOTED, "ENIP - well-formed header, ");
    return ICS_RESULT_OK;
}

static IcsParseResult parseCmdNop(Enip *enip, iecBYTE *data, iecUDINT octets, int *po)
{
    int o = *po;
    EnipHeader *header = enip->header;
    EnipCmdNop **nop = &(enip->nop);
    ICS_TMEMORY_P(current, EnipCmdNop);
    *nop = current;
    ICS_BYTES(current->junk, header->length);
    if(header->status != 0)
        current->statusNotZero = 1;
    if(header->options != 0)
        current->optionsNotZero = 1;
    *po = o;
    icsSaveHex(data, octets, octets, ICS_HEXDUMP_QUOTED, "ENIP - well-formed 'NoOp', ");
    return ICS_RESULT_OK;
}

static IcsParseResult parseCmdListIdentity(Enip *enip, iecBYTE *data, iecUDINT octets, int *po)
{
    if(enip->header->length == 0)
        return ICS_RESULT_OK;
    int o = *po;
    EnipCmdListIdentity **listIdentity = &(enip->listIdentity);
    EnipCmdListIdentity *current = NULL;
    ICS_UINT(iecUINT itemCount);
    iecUINT ui;
    for(ui=0; ui < itemCount; ui++) {
        if(current == NULL) {
            ICS_TMEMORY_P(newListIdentity, EnipCmdListIdentity);
            current = *listIdentity = newListIdentity;
        }
        else {
            ICS_TMEMORY_P(newListIdentity, EnipCmdListIdentity);
            current = current->next = newListIdentity;
        }
        ICS_UINT(current->type);
        ICS_UINT(current->length);
        ICS_UINT(current->version);
        ICS_INT_BE(current->address.family);
        ICS_UINT_BE(current->address.port);
        ICS_UDINT_BE(current->address.address);
        ICS_USINTS(current->address.zero, 8);
        ICS_UINT(current->vendorId);
        ICS_UINT(current->deviceType);
        ICS_UINT(current->productCode);
        ICS_USINTS(current->revision, 2);
        ICS_WORD(current->status);
        ICS_UDINT(current->serial);
        ICS_SHORTSTRING(current->name);
        ICS_USINT(current->state);
    }
    *po = o;
    icsSaveHex(data, octets, octets, ICS_HEXDUMP_QUOTED, "ENIP - well-formed 'ListIdentity', ");
    return ICS_RESULT_OK;
}

static IcsParseResult parseCmdListInterfaces(IcsStack *stack, Enip *enip, iecBYTE *data, iecUDINT octets, int *po)
{
    if(enip->header->length == 0)
        return ICS_RESULT_OK;
    int o = *po;
    EnipCmdListInterfaces **listInterfaces = &(enip->listInterfaces);
    EnipCmdListInterfaces *current = NULL;
    IcsParseResult r = ICS_RESULT_OK;
    ICS_UINT(iecUINT itemCount);
    if(itemCount == 0) {
        ICS_TMEMORY_P(newListInterfaces, EnipCmdListInterfaces);
        *listInterfaces = newListInterfaces;
    } else {
        iecUINT ui;
        for(ui=0; ui < itemCount; ui++) {
            if(current == NULL) {
                ICS_TMEMORY_P(newListInterfaces, EnipCmdListInterfaces);
                current = *listInterfaces = newListInterfaces;
            }
            else {
                ICS_TMEMORY_P(newListInterfaces, EnipCmdListInterfaces);
                current = current->next = newListInterfaces;
            }
            ICS_UINT(current->type);
            ICS_UINT(current->length);
            if((r = parseCPF(&(current->cpf), data, octets, &o)) == ICS_RESULT_OK) {
                enip->cpf = current->cpf;
                r = parseCPFRound2(current->cpf, stack);
            }
        }
    }
    *po = o;
    icsSaveHex(data, octets, octets, ICS_HEXDUMP_QUOTED, "ENIP - well-formed 'ListInterfaces', ");
    return r;
}

static IcsParseResult parseCmdRegisterSession(Enip *enip, iecBYTE *data, iecUDINT octets, int *po)
{
    int o = *po;
    EnipHeader *header = enip->header;
    EnipCmdRegisterSession **registerSession = &(enip->registerSession);
    ICS_TMEMORY_P(current, EnipCmdRegisterSession);
    *registerSession = current;
    if(header->length != 4) {
        current->hasInvalidDataLength = iecTRUE;
        return ICS_RESULT_OK;
    }
    ICS_UINT(current->version);
    ICS_UINT(current->flags);
    if(current->flags != 0)
        current->hasNonZeroOptions = iecTRUE;
    *po = o;
    icsSaveHex(data, octets, octets, ICS_HEXDUMP_QUOTED, "ENIP - well-formed 'RegisterSession' (0x%04x), ", header->session);
    return ICS_RESULT_OK;
}

static IcsParseResult parseCmdUnregisterSession(Enip *enip, iecBYTE *data, iecUDINT octets, int *po)
{
    ICS_IGNORE(data);
    ICS_IGNORE(octets);
    ICS_IGNORE(po);
    EnipHeader *header = enip->header;
    EnipCmdUnregisterSession **unregisterSession = &(enip->unregisterSession);
    ICS_TMEMORY_P(current, EnipCmdUnregisterSession);
    *unregisterSession = current;
    if(header->session == 0)
        current->hasZeroSession = iecTRUE;
    if(header->length != 0)
        current->hasInvalidDataLength = iecTRUE;
    if(header->status != 0)
        current->hasNonZeroStatus = iecTRUE;
    if(header->options != 0)
        current->hasNonZeroOptions = iecTRUE;
    icsSaveHex(data, octets, octets, ICS_HEXDUMP_QUOTED, "ENIP - well-formed 'ListInterfaces' (0x%04x), ", header->session);
    return ICS_RESULT_OK;
}

static IcsParseResult parseCmdListServices(Enip *enip, iecBYTE *data, iecUDINT octets, int *po)
{
    int o = *po;
    if(enip->header->length == 0)
        return ICS_RESULT_OK;
    EnipCmdListServices **listServices = &(enip->listServices);
    EnipCmdListServices *current = NULL;
    ICS_UINT(iecUINT itemCount);
    iecUINT ui;
    for(ui=0; ui < itemCount; ui++) {
        if(current == NULL) {
            ICS_TMEMORY_P(newListServices, EnipCmdListServices);
            current = *listServices = newListServices;
        }
        else {
            ICS_TMEMORY_P(newListServices, EnipCmdListServices);
            current = current->next = newListServices;
        }
        ICS_UINT(current->type);
        ICS_UINT(current->length);
        ICS_UINT(current->version);
        ICS_UINT(current->capabilities);
        ICS_SINTS(current->name, 16);
        if(current->capabilities & 0x0020)
            current->doesTCP = iecTRUE;
        if(current->capabilities & 0x0100)
            current->doesUDP = iecTRUE;
    }
    *po = o;
    icsSaveHex(data, octets, octets, ICS_HEXDUMP_QUOTED, "ENIP - well-formed 'ListServices' (tcp:%u, udp:%u), ", current->doesTCP, current->doesUDP);
    return ICS_RESULT_OK;
}

static IcsParseResult parseCmdSendRRData(IcsStack *stack, Enip *enip, iecBYTE *data, iecUDINT octets, int *po)
{
    int o = *po;
    EnipCmdSendRRData **sendRRData = &(enip->sendRRData);
    ICS_TMEMORY_P(current, EnipCmdSendRRData);
    *sendRRData = current;
    IcsParseResult r = ICS_RESULT_OK;
    ICS_UDINT(current->interface);
    ICS_UINT(current->timeout);
    if((r = parseCPF(&(current->cpf), data, octets, &o)) == ICS_RESULT_OK) {
        enip->cpf = current->cpf;
        r = parseCPFRound2(current->cpf, stack);
    }
    *po = o;
    icsSaveHex(data, octets, octets, ICS_HEXDUMP_QUOTED, "ENIP - well-formed 'SendRRData' (in:0x%04x, to:%u), ", current->interface, current->timeout);
    return r;
}

static IcsParseResult parseCmdSendUnitData(IcsStack *stack, Enip *enip, iecBYTE *data, iecUDINT octets, int *po)
{
    int o = *po;
    EnipCmdSendUnitData **sendUnitData = &(enip->sendUnitData);
    ICS_TMEMORY_P(current, EnipCmdSendUnitData);
    *sendUnitData = current;
    IcsParseResult r = ICS_RESULT_OK;
    ICS_UDINT(current->interface);
    ICS_UINT(current->timeout);
    if((r = parseCPF(&(current->cpf), data, octets, &o)) == ICS_RESULT_OK) {
        enip->cpf = current->cpf;
        r = parseCPFRound2(current->cpf, stack);
    }
    *po = o;
    icsSaveHex(data, octets, octets, ICS_HEXDUMP_QUOTED, "ENIP - well-formed 'SendUnitData' (in:0x%04x, to:%u), ", current->interface, current->timeout);
    return r;
}

static IcsParseResult parseCmdIndicateStatus(Enip *enip, iecBYTE *data, iecUDINT octets, int *po)
{
    ICS_IGNORE(data);
    ICS_IGNORE(octets);
    ICS_IGNORE(po);
    EnipCmdIndicateStatus **indicateStatus = &(enip->indicateStatus);
    ICS_TMEMORY_P(current, EnipCmdIndicateStatus);
    *indicateStatus = current;
    current->isStatusRequested = iecTRUE;
    icsSaveHex(data, octets, octets, ICS_HEXDUMP_QUOTED, "ENIP - well-formed 'IndicateStatus', ");
    return ICS_RESULT_OK;
}

static IcsParseResult parseCmdCancel(Enip *enip, iecBYTE *data, iecUDINT octets, int *po)
{
    ICS_IGNORE(data);
    ICS_IGNORE(octets);
    ICS_IGNORE(po);
    EnipCmdCancel **cancel = &(enip->cancel);
    ICS_TMEMORY_P(current, EnipCmdCancel);
    *cancel = current;
    current->isCanceled = iecTRUE;
    icsSaveHex(data, octets, octets, ICS_HEXDUMP_QUOTED, "ENIP - well-formed 'Cancel', ");
    return ICS_RESULT_OK;
}

static IcsParseResult parseCmdUnknown(Enip *enip, iecBYTE *data, iecUDINT octets, int *po)
{
    int o = *po;
    EnipCmdUnknown **unknown = &(enip->unknown);
    ICS_FREE(*unknown);
    ICS_TMEMORY_P(current, EnipCmdUnknown);
    *unknown = current;
    if(enip->header->length > 0) {
        current->length = enip->header->length;
        ICS_BYTES(current->data, current->length);
    }
    *po = o;
    icsSaveHex(data, octets, octets, ICS_HEXDUMP_QUOTED, "ENIP - well-formed 'Unknown', ");
    return ICS_RESULT_OK;
}

static IcsHash *globals;
iecDINT icsInitializeEnip(char *(*configLoader)(char *name))
{
    ICS_FETCH_CONFIG_NUMBER(configLoader, "libics.ENIP.transactionmax");
    ICS_FETCH_CONFIG_STRING(configLoader, "libics.ENIP.avoidfuncs");
    ICS_FETCH_CONFIG_STRING(configLoader, "libics.ENIP.servertcpports");
    ICS_FETCH_CONFIG_STRING(configLoader, "libics.ENIP.serverudpports");

    iecUINT transMax;
    if((transMax = icsConfigGetNumber("libics.ENIP.transactionmax")) != ICS_DEFAULT_MAXTRANS)
        transactionMaxima[ICS_PROTO_ENIP] = transMax;

    if(globals == NULL) {
        if((globals = icsHashCreate(256, 90, SCHA_DEFAULT)) != NULL) {
            int i;
            for(i=0; enipCommands[i].name; i++)
                icsHashSetItem(globals, enipCommands[i].name, icsCreatePredicateValue(SPVT_NUMERIC, enipCommands[i].value, NULL));
            for(i=0; enipStatusCodes[i].name; i++)
                icsHashSetItem(globals, enipStatusCodes[i].name, icsCreatePredicateValue(SPVT_NUMERIC, enipStatusCodes[i].value, NULL));
            for(i=0; enipItemIds[i].name; i++)
                icsHashSetItem(globals, enipItemIds[i].name, icsCreatePredicateValue(SPVT_NUMERIC, enipItemIds[i].value, NULL));
        }
    }

    if(avoidFuncs == NULL) {
        iecSINT *list = icsConfigGetString("libics.ENIP.avoidfuncs");
        if(list != NULL)
            avoidFuncs = icsNumberArrayFromCommaList(list, 0, &avoidFuncCount);
    }

    return globals == NULL ? 0 : 1;
}

void icsUninitializeEnip(void)
{
    if(globals != NULL)
        icsFreePredicateHash(globals);
    if(avoidFuncs != NULL)
        ICS_FREE(avoidFuncs);
}

IcsDetectItem *icsMungeEnip(const char *keyword, const char *options)
{
    ICS_TMEMORY(item, IcsDetectItem);
    item->predicate = NULL;
    item->globals   = globals;
    item->constants = icsHashCreate(64, 90, SCHA_DEFAULT);
    item->protocol  = ICS_PROTO_ENIP;

    if(keyword == NULL || strcmp(keyword, "enip") == 0)
        item->predicate = icsStrdup(options);
    else
    if(strcmp(keyword, "enip_func") == 0) {
        IcsPredicateValue *commands = icsNumberArrayFromKeywordParameters(options, enipCommands);
        if(commands != NULL) {
            icsHashSetItem(item->constants, "sig.commands", commands);
            item->predicate = icsStrdup(ENIP_PREDICATE_FUNCTION);
        }
    }
    else
    if(strcmp(keyword, "enip_stat") == 0) {
        IcsPredicateValue *cmds = icsNumberArrayFromKeywordParameters(options, enipStatusCodes);
        if(cmds != NULL) {
            icsHashSetItem(item->constants, "sig.statuses", cmds);
            item->predicate = icsStrdup(ENIP_PREDICATE_STATUS);
        }
    }
    else
    if(strcmp(keyword, "enip_type") == 0) {
        IcsPredicateValue *types = icsNumberArrayFromKeywordParameters(options, enipItemIds);
        if(types != NULL) {
            icsHashSetItem(item->constants, "sig.cpftypes", types);
            item->predicate = icsStrdup(ENIP_PREDICATE_CPFTYPES);
        }
    }
    return item;
}

void icsFreeEnip(IcsOpaque *p)
{
    Enip *enip = p;
    if(enip != NULL) {
        if(enip->header != NULL) {
            ICS_FREE(enip->header->context);
            ICS_FREE(enip->header);
        }
        /* don't do this here, gets freed in individual round2 item
        if(enip->cpf != NULL) {
            EnipDataItem *item = enip->cpf->item;
            while(item != NULL) {
                EnipDataItem *next = item->next;
                ICS_FREE(item->data);
                ICS_FREE(item);
                item = next;
            }
            ICS_FREE(enip->cpf);
        }
        */
        ICS_FREE(enip->cancel);
        ICS_FREE(enip->indicateStatus);
        EnipCmdListIdentity *identity = enip->listIdentity;
        while(identity != NULL) {
            EnipCmdListIdentity *next = identity->next;
            ICS_FREE(identity->name->string);
            ICS_FREE(identity->name);
            ICS_FREE(identity->revision);
            ICS_FREE(identity);
            identity = next;
        }
        EnipCmdListServices *services = enip->listServices;
        while(services != NULL) {
            EnipCmdListServices *next = services->next;
            ICS_FREE(services->name);
            ICS_FREE(services);
            services = next;
        }
        EnipCmdListInterfaces *interface = enip->listInterfaces;
        while(interface != NULL) {
            EnipCmdListInterfaces *next = interface->next;
            if(interface->cpf != NULL) {
                EnipDataItem *item = interface->cpf->item;
                while(item != NULL) {
                    EnipDataItem *next = item->next;
                    ICS_FREE(item->data);
                    ICS_FREE(item);
                    item = next;
                }
                ICS_FREE(enip->listInterfaces->cpf);
            }
            ICS_FREE(interface);
            interface = next;
        }
        if(enip->nop != NULL) {
            ICS_FREE(enip->nop->junk);
            ICS_FREE(enip->nop);
        }
        ICS_FREE(enip->registerSession);
        ICS_FREE(enip->unregisterSession);
        if(enip->sendRRData != NULL) {
            if(enip->sendRRData->cpf != NULL) {
                EnipDataItem *item = enip->sendRRData->cpf->item;
                while(item != NULL) {
                    EnipDataItem *next = item->next;
                    ICS_FREE(item->data);
                    ICS_FREE(item);
                    item = next;
                }
                ICS_FREE(enip->sendRRData->cpf);
            }
            ICS_FREE(enip->sendRRData);
        }
        if(enip->sendUnitData != NULL) {
            if(enip->sendUnitData->cpf != NULL) {
                EnipDataItem *item = enip->sendUnitData->cpf->item;
                while(item != NULL) {
                    EnipDataItem *next = item->next;
                    ICS_FREE(item->data);
                    ICS_FREE(item);
                    item = next;
                }
                ICS_FREE(enip->sendUnitData->cpf);
            }
            ICS_FREE(enip->sendUnitData);
        }
        if(enip->unknown != NULL) {
            ICS_FREE(enip->unknown->data);
            ICS_FREE(enip->unknown);
        }
        ICS_FREE(enip);
    }
}

IcsParseResult icsParseEnip(IcsLayer startLayer, IcsMode mode, iecBYTE *data, iecUDINT octets, IcsStack *stack)
{
    ICS_IGNORE(mode);
    if((startLayer & ICS_LAYER_APPLICATION) != ICS_LAYER_APPLICATION)
        return ICS_RESULT_UNSUPPORTEDLAYER;

    int r, o = 0;

    EnipHeader *header;
    if((r = parseHeader(&header, data, octets, &o)) != ICS_RESULT_OK)
        return r;

    iecSINT transactionKey[32];
    snprintf(transactionKey, sizeof(transactionKey), "%08x:%04x:%08x",
             header->session, header->command, *((iecUDINT *) header->context));

    IcsTransaction *transaction = NULL;
    if(mode == ICS_MODE_RQ)
        transaction = icsTransactionNew(stack, ICS_PROTO_ENIP, transactionKey, alloc, ENIP_TRX_TTL, iecFALSE);
    else
    if(mode == ICS_MODE_RS)
        //if((transaction = icsTransactionGet(stack, ICS_PROTO_ENIP, transactionKey)) == NULL)
            transaction = icsTransactionNew(stack, ICS_PROTO_ENIP, transactionKey, alloc, ENIP_TRX_TTL, iecFALSE);

    if(transaction == NULL) {
        ICS_FREE(header);
        return ICS_RESULT_OUTOFMEMORY;
    }

    Enip *enip = transaction->opaque;
    enip->header = header;

    switch(enip->header->command) {
        case ENIP_CMD_NOP: {
            r = parseCmdNop(enip, data, octets, &o);
        } break;

        case ENIP_CMD_LISTIDENTITY: {
            r = parseCmdListIdentity(enip, data, octets, &o);
        } break;

        case ENIP_CMD_LISTINTERFACES: {
            r = parseCmdListInterfaces(stack, enip, data, octets, &o);
        } break;

        case ENIP_CMD_REGISTERSESSION: {
            r = parseCmdRegisterSession(enip, data, octets, &o);
        } break;

        case ENIP_CMD_UNREGISTERSESSION: {
            r = parseCmdUnregisterSession(enip, data, octets, &o);
        } break;

        case ENIP_CMD_LISTSERVICES: {
            r = parseCmdListServices(enip, data, octets, &o);
        } break;

        case ENIP_CMD_SENDRRDATA: {
            if((r = parseCmdSendRRData(stack, enip, data, octets, &o)) == ICS_RESULT_OK)
                if(mode == ICS_MODE_RQ)
                    icsTransactionSetTTL(transaction, enip->sendRRData->timeout);
        } break;

        case ENIP_CMD_SENDUNITDATA: {
            r = parseCmdSendUnitData(stack, enip, data, octets, &o);
        } break;

        case ENIP_CMD_INDICATESTATUS: {
            r = parseCmdIndicateStatus(enip, data, octets, &o);
        } break;

        case ENIP_CMD_CANCEL: {
            r = parseCmdCancel(enip, data, octets, &o);
        } break;

        default: {
            r = parseCmdUnknown(enip, data, octets, &o);
        } break;
    }

    shoveVariables(transaction);

    if(r == ICS_RESULT_OK) {
        if(mode == ICS_MODE_RS)
            icsTransactionMarkComplete(transaction);
    }
    else {
        icsTransactionMarkFailed(transaction, r);
        o = octets;
    }

    icsSaveHex(data, octets, o, ICS_HEXDUMP_QUOTED, "ENIP - fully well-formed, ");

    if(octets - o >= ENIP_HDR_LEN)
        return icsParseEnip(startLayer, mode, data + o, octets - o, stack);

    return r;
}

IcsProtocol icsProbeEnip(IcsLayer startLayer, iecBYTE *data, iecUDINT octets)
{
    if((startLayer & ICS_LAYER_APPLICATION) != ICS_LAYER_APPLICATION)
        return ICS_RESULT_UNSUPPORTEDLAYER;

    int o = 0;
    EnipHeader *header;
    if(parseHeader(&header, data, octets, &o) != ICS_RESULT_OK)
        return ICS_PROTO_NONE;
    if(header != NULL) {
        ICS_FREE(header->context);
        ICS_FREE(header);
    }
    return ICS_PROTO_ENIP;
}
