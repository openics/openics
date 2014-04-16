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
 * DNP3 Primitives.
 *
 */

#include "icsdnp3.h"

static IcsNumericAssociation dnp3Functions[] = {
    { 0x00, "confirm" },
    { 0x01, "read" },
    { 0x02, "write" },
    { 0x03, "select" },
    { 0x04, "operate" },
    { 0x05, "direct_operate" },
    { 0x06, "direct_operate_nr" },
    { 0x07, "immed_freeze" },
    { 0x08, "immed_freeze_nr" },
    { 0x09, "freeze_clear" },
    { 0x0A, "freeze_clear_nr" },
    { 0x0B, "freeze_at_time" },
    { 0x0C, "freeze_at_time_nr" },
    { 0x0D, "cold_restart" },
    { 0x0E, "warm_restart" },
    { 0x0F, "initialize_data" },
    { 0x10, "initialize_appl" },
    { 0x11, "start_appl" },
    { 0x12, "stop_appl" },
    { 0x13, "save_config" },
    { 0x14, "enable_unsolicited" },
    { 0x15, "disable_unsolicited" },
    { 0x16, "assign_class" },
    { 0x17, "delay_measure" },
    { 0x18, "record_current_time" },
    { 0x19, "open_file" },
    { 0x1A, "close_file" },
    { 0x1B, "delete_file" },
    { 0x1C, "get_file_info" },
    { 0x1D, "authenticate_file" },
    { 0x1E, "abort_file" },
    { 0x1F, "activate_config" },
    { 0x20, "authenticate_req" },
    { 0x21, "authenticate_err" },
    { 0x81, "response" },
    { 0x82, "unsolicited_response" },
    { 0x83, "authenticate_response" },
    { 0x00, NULL }
};

static IcsNumericAssociation dnp3InternalIndications[] = {
    { 0x0100, "all_stations" },
    { 0x0200, "class_1_events" },
    { 0x0400, "class_2_events" },
    { 0x0800, "class_3_events" },
    { 0x1000, "need_time" },
    { 0x2000, "local_control" },
    { 0x4000, "device_trouble" },
    { 0x8000, "device_restart" },
    { 0x0001, "no_func_code_support" },
    { 0x0002, "object_unknown" },
    { 0x0004, "parameter_error" },
    { 0x0008, "event_buffer_overflow" },
    { 0x0010, "already_executing" },
    { 0x0020, "config_corrupt" },
    { 0x0040, "reserved_2" },
    { 0x0080, "reserved_1" },
    { 0x0000, NULL }
};

static uint16_t crctable[256] =
{
    0x0000, 0x365E, 0x6CBC, 0x5AE2, 0xD978, 0xEF26, 0xB5C4, 0x839A,
    0xFF89, 0xC9D7, 0x9335, 0xA56B, 0x26F1, 0x10AF, 0x4A4D, 0x7C13,
    0xB26B, 0x8435, 0xDED7, 0xE889, 0x6B13, 0x5D4D, 0x07AF, 0x31F1,
    0x4DE2, 0x7BBC, 0x215E, 0x1700, 0x949A, 0xA2C4, 0xF826, 0xCE78,
    0x29AF, 0x1FF1, 0x4513, 0x734D, 0xF0D7, 0xC689, 0x9C6B, 0xAA35,
    0xD626, 0xE078, 0xBA9A, 0x8CC4, 0x0F5E, 0x3900, 0x63E2, 0x55BC,
    0x9BC4, 0xAD9A, 0xF778, 0xC126, 0x42BC, 0x74E2, 0x2E00, 0x185E,
    0x644D, 0x5213, 0x08F1, 0x3EAF, 0xBD35, 0x8B6B, 0xD189, 0xE7D7,
    0x535E, 0x6500, 0x3FE2, 0x09BC, 0x8A26, 0xBC78, 0xE69A, 0xD0C4,
    0xACD7, 0x9A89, 0xC06B, 0xF635, 0x75AF, 0x43F1, 0x1913, 0x2F4D,
    0xE135, 0xD76B, 0x8D89, 0xBBD7, 0x384D, 0x0E13, 0x54F1, 0x62AF,
    0x1EBC, 0x28E2, 0x7200, 0x445E, 0xC7C4, 0xF19A, 0xAB78, 0x9D26,
    0x7AF1, 0x4CAF, 0x164D, 0x2013, 0xA389, 0x95D7, 0xCF35, 0xF96B,
    0x8578, 0xB326, 0xE9C4, 0xDF9A, 0x5C00, 0x6A5E, 0x30BC, 0x06E2,
    0xC89A, 0xFEC4, 0xA426, 0x9278, 0x11E2, 0x27BC, 0x7D5E, 0x4B00,
    0x3713, 0x014D, 0x5BAF, 0x6DF1, 0xEE6B, 0xD835, 0x82D7, 0xB489,
    0xA6BC, 0x90E2, 0xCA00, 0xFC5E, 0x7FC4, 0x499A, 0x1378, 0x2526,
    0x5935, 0x6F6B, 0x3589, 0x03D7, 0x804D, 0xB613, 0xECF1, 0xDAAF,
    0x14D7, 0x2289, 0x786B, 0x4E35, 0xCDAF, 0xFBF1, 0xA113, 0x974D,
    0xEB5E, 0xDD00, 0x87E2, 0xB1BC, 0x3226, 0x0478, 0x5E9A, 0x68C4,
    0x8F13, 0xB94D, 0xE3AF, 0xD5F1, 0x566B, 0x6035, 0x3AD7, 0x0C89,
    0x709A, 0x46C4, 0x1C26, 0x2A78, 0xA9E2, 0x9FBC, 0xC55E, 0xF300,
    0x3D78, 0x0B26, 0x51C4, 0x679A, 0xE400, 0xD25E, 0x88BC, 0xBEE2,
    0xC2F1, 0xF4AF, 0xAE4D, 0x9813, 0x1B89, 0x2DD7, 0x7735, 0x416B,
    0xF5E2, 0xC3BC, 0x995E, 0xAF00, 0x2C9A, 0x1AC4, 0x4026, 0x7678,
    0x0A6B, 0x3C35, 0x66D7, 0x5089, 0xD313, 0xE54D, 0xBFAF, 0x89F1,
    0x4789, 0x71D7, 0x2B35, 0x1D6B, 0x9EF1, 0xA8AF, 0xF24D, 0xC413,
    0xB800, 0x8E5E, 0xD4BC, 0xE2E2, 0x6178, 0x5726, 0x0DC4, 0x3B9A,
    0xDC4D, 0xEA13, 0xB0F1, 0x86AF, 0x0535, 0x336B, 0x6989, 0x5FD7,
    0x23C4, 0x159A, 0x4F78, 0x7926, 0xFABC, 0xCCE2, 0x9600, 0xA05E,
    0x6E26, 0x5878, 0x029A, 0x34C4, 0xB75E, 0x8100, 0xDBE2, 0xEDBC,
    0x91AF, 0xA7F1, 0xFD13, 0xCB4D, 0x48D7, 0x7E89, 0x246B, 0x1235
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

static char *reverseLookupFunction(iecUSINT code)
{
    int i;
    for(i=0; dnp3Functions[i].name; i++)
        if(dnp3Functions[i].value == code)
            return dnp3Functions[i].name;
    return NULL;
}

/*
static IcsOpaque *alloc(void)
{
    ICS_TMEMORY(dnp3, Dnp3);
    return dnp3;
}
*/

static iecUINT calculateCRC(const iecBYTE *data, iecUDINT octets)
{
    iecUINT crc = 0;
    while(octets-- > 0)
        crc = crctable[(crc ^ *data++) & 0xff] ^ (crc >> 8);
    return ~crc;
}

static void shoveVariables(IcsTransaction *transaction)
{
    if(transaction != NULL) {
        if(transaction->variables != NULL)
            icsFreePredicateHash(transaction->variables);
        Dnp3 *dnp3;
        if((dnp3 = transaction->opaque) != NULL) {
            if((transaction->variables = icsHashCreate(1024, 90, SCHA_DEFAULT)) != NULL) {

                ICS_SHOVENUMBER("dnp3.datalink.function",              dnp3->dataLinkLayer->controlFunction);
                ICS_SHOVENUMBER("dnp3.datalink.control",               dnp3->dataLinkLayer->controlParameter);
                ICS_SHOVENUMBER("dnp3.datalink.source",                dnp3->dataLinkLayer->source);
                ICS_SHOVENUMBER("dnp3.datalink.destination",           dnp3->dataLinkLayer->destination);
                ICS_SHOVENUMBER("dnp3.datalink.hasInvalidChecksum",    dnp3->dataLinkLayer->hasInvalidChecksum);

                if(dnp3->transportLayer != NULL) {
                    ICS_SHOVENUMBER("dnp3.transport.control",              dnp3->transportLayer->control);
                    ICS_SHOVENUMBER("dnp3.transport.sequence",             dnp3->transportLayer->sequence);
                    ICS_SHOVENUMBER("dnp3.transport.hasFirstFragment",     dnp3->transportLayer->hasFirstFragment);
                    ICS_SHOVENUMBER("dnp3.transport.hasLastFragment",      dnp3->transportLayer->hasLastFragment);
                    ICS_SHOVENUMBER("dnp3.transport.hasSequenceError",     dnp3->transportLayer->hasSequenceError);
                    ICS_SHOVENUMBER("dnp3.transport.hasInvalidChecksum",   dnp3->transportLayer->hasInvalidChecksum);
                }

                if(dnp3->applicationLayer) {
                    ICS_SHOVENUMBER("dnp3.application.control",            dnp3->applicationLayer->control);
                    ICS_SHOVENUMBER("dnp3.application.function",           dnp3->applicationLayer->function);
                    ICS_SHOVENUMBER("dnp3.application.indication",         dnp3->applicationLayer->indication);
                    ICS_SHOVENUMBER("dnp3.application.confirm",            dnp3->applicationLayer->confirm);
                    ICS_SHOVENUMBER("dnp3.application.unsolicited",        dnp3->applicationLayer->unsolicited);
                    ICS_SHOVENUMBER("dnp3.application.hasInvalidFunction", dnp3->applicationLayer->hasInvalidFunction);

                    ICS_SHOVENUMBER("dnp3.application.object.type",        dnp3->applicationLayer->object.type);
                    ICS_SHOVENUMBER("dnp3.application.object.index",       dnp3->applicationLayer->object.index);
                    ICS_SHOVENUMBER("dnp3.application.object.qualifier",   dnp3->applicationLayer->object.qualifier);
                }
            }
        }
    }
}

static IcsHash *globals;
iecDINT icsInitializeDnp3(char *(*configLoader)(char *name))
{
    ICS_FETCH_CONFIG_NUMBER(configLoader, "libics.DNP3.transactionmax");
    ICS_FETCH_CONFIG_STRING(configLoader, "libics.DNP3.avoidfuncs");
    ICS_FETCH_CONFIG_STRING(configLoader, "libics.DNP3.servertcpports");
    ICS_FETCH_CONFIG_STRING(configLoader, "libics.DNP3.serverudpports");

    iecUINT transMax;
    if((transMax = icsConfigGetNumber("libics.DNP3.transactionmax")) != ICS_DEFAULT_MAXTRANS)
        transactionMaxima[ICS_PROTO_DNP3] = transMax;

    if(globals == NULL) {
        if((globals = icsHashCreate(256, 90, SCHA_DEFAULT)) != NULL) {
            int i;
            for(i=0; dnp3Functions[i].name; i++)
                icsHashSetItem(globals, dnp3Functions[i].name, icsCreatePredicateNumber(dnp3Functions[i].value));
            for(i=0; dnp3InternalIndications[i].name; i++)
                icsHashSetItem(globals, dnp3InternalIndications[i].name, icsCreatePredicateNumber(dnp3InternalIndications[i].value));
        }
    }

    if(avoidFuncs == NULL) {
        iecSINT *list = icsConfigGetString("libics.DNP3.avoidfuncs");
        if(list != NULL)
            avoidFuncs = icsNumberArrayFromCommaList(list, 0, &avoidFuncCount);
    }

    return globals == NULL ? 0 : 1;
}

void icsUninitializeDnp3(void)
{
    if(globals != NULL)
        icsFreePredicateHash(globals);
    if(avoidFuncs != NULL)
        ICS_FREE(avoidFuncs);
}

IcsDetectItem *icsMungeDnp3(const iecSINT *keyword, const iecSINT *options)
{
    ICS_TMEMORY(item, IcsDetectItem);
    item->predicate = NULL;
    item->globals   = globals;
    item->constants = icsHashCreate(64, 90, SCHA_DEFAULT);
    item->protocol  = ICS_PROTO_DNP3;

    if(keyword == NULL || strcmp(keyword, "dnp3") == 0)
        item->predicate = icsStrdup(options);
    else
    if(strcmp(keyword, "dnp3_func") == 0) {
        IcsPredicateValue *funcs = icsNumberArrayFromKeywordParameters(options, dnp3Functions);
        if(funcs != NULL) {
            icsHashSetItem(item->constants, "sig.functions", funcs);
            item->predicate = icsStrdup(DNP3_PREDICATE_FUNCTION);
        }
    }
    else
    if(strcmp(keyword, "dnp3_src") == 0) {
        IcsPredicateValue *sources = icsNumberArrayFromKeywordParameters(options, NULL);
        if(sources != NULL) {
            icsHashSetItem(item->constants, "sig.sources", sources);
            item->predicate = icsStrdup(DNP3_PREDICATE_SOURCE);
        }
    }
    else
    if(strcmp(keyword, "dnp3_dst") == 0) {
        IcsPredicateValue *destinations = icsNumberArrayFromKeywordParameters(options, NULL);
        if(destinations != NULL) {
            icsHashSetItem(item->constants, "sig.destinations", destinations);
            item->predicate = icsStrdup(DNP3_PREDICATE_DESTINATION);
        }
    }
    else
    if(strcmp(keyword, "dnp3_iin") == 0) {
        IcsPredicateValue *indications = icsBitfieldFromKeywordParameters(options, dnp3InternalIndications);
        if(indications != NULL) {
            icsHashSetItem(item->constants, "sig.indications", indications);
            item->predicate = icsStrdup(DNP3_PREDICATE_INDICATION);
        }
    }
    else
    if(strcmp(keyword, "dnp3_obj") == 0) {
        IcsPredicateValue *objspec = icsNumberArrayFromKeywordParameters(options, NULL);
        if(objspec != NULL) {
            iecSINT *predicate = NULL;
            if(objspec->count > 0) {
                icsHashSetItem(item->constants, "sig.objtype", icsGetPredicateArrayItem(objspec, 0));
                predicate = DNP3_PREDICATE_OBJECTTYPE;
            }
            if(objspec->count > 1) {
                icsHashSetItem(item->constants, "sig.objindex", icsGetPredicateArrayItem(objspec, 1));
                predicate = DNP3_PREDICATE_OBJECTTYPE " && "
                            DNP3_PREDICATE_OBJECTINDEX;
            }
            if(objspec->count > 2) {
                icsHashSetItem(item->constants, "sig.objqualifier", icsGetPredicateArrayItem(objspec, 2));
                predicate = DNP3_PREDICATE_OBJECTTYPE " && "
                            DNP3_PREDICATE_OBJECTINDEX " && "
                            DNP3_PREDICATE_OBJECTQUALIFIER;
            }
            if(predicate != NULL)
                item->predicate = icsStrdup(predicate);
            icsFreePredicateValue(&objspec);
        }
    }
    else
    if(strcmp(keyword, "dnp3_stat") == 0) {
        IcsPredicateValue *v, *errors = icsStringArrayFromKeywordParameters(options);
        iecSINT *dlcrcPredicate = DNP3_PREDICATE_FALSE;
        if((v = icsFindPredicateArrayStringItem(errors, "dlcrc")) != NULL) {
            dlcrcPredicate = DNP3_PREDICATE_ERRORBADDLCRC;
            icsFreePredicateValue(&v);
        }
        iecSINT *tlcrcPredicate = DNP3_PREDICATE_FALSE;
        if((v = icsFindPredicateArrayStringItem(errors, "tlcrc")) != NULL) {
            tlcrcPredicate = DNP3_PREDICATE_ERRORBADTLCRC;
            icsFreePredicateValue(&v);
        }
        iecSINT *alfcnPredicate = DNP3_PREDICATE_FALSE;
        if((v = icsFindPredicateArrayStringItem(errors, "alfcn")) != NULL) {
            alfcnPredicate = DNP3_PREDICATE_ERRORBADALFUNC;
            icsFreePredicateValue(&v);
        }
        int plen = strlen(dlcrcPredicate) + strlen(tlcrcPredicate) + strlen(alfcnPredicate) + 16;
        ICS_SMEMORY(newPredicate, iecSINT, plen);
        if((item->predicate = newPredicate) != NULL)
            snprintf(item->predicate, plen, "%s || %s || %s", dlcrcPredicate, tlcrcPredicate, alfcnPredicate);
        icsFreePredicateValue(&errors);
    }
    return item;
}

void icsFreeDnp3(IcsOpaque *p)
{
    Dnp3 *dnp3 = p;
    if(dnp3 != NULL) {
        ICS_FREE(dnp3->dataLinkLayer);
        Dnp3TLFragment *fragment = dnp3->transportLayer->fragment;
        while(fragment != NULL) {
            Dnp3TLFragment *next = fragment->next;
            ICS_FREE(fragment->data);
            ICS_FREE(fragment);
            fragment = next;
        }
        ICS_FREE(dnp3->transportLayer);
        ICS_FREE(dnp3->applicationLayer);
        ICS_FREE(dnp3);
    }
}

static IcsParseResult parseDataLinkLayer(Dnp3DataLinkLayer **dataLinkLayer, iecBYTE *data, iecUDINT octets, int *po)
{
    int o = *po;

    ICS_UINT_BE(iecUINT signature);
    if(signature != DNP3_SIGNATURE) {
        icsSaveHex(data, octets, o, ICS_HEXDUMP_QUOTED, "DNP3 - invalid dl signature (0x%04x), ", signature);
        return ICS_RESULT_INVALID;
    }

    ICS_TMEMORY_P(current, Dnp3DataLinkLayer);
    *dataLinkLayer = current;
    current->signature = signature;
    ICS_USINT(current->length);
    ICS_USINT(current->control);

    if((current->control & DNP3_DLCTL_DIRECTION) == DNP3_DLCTL_DIRECTION) {
        ICS_UINT(current->source);
        ICS_UINT(current->destination);
    }
    else {
        current->isResponse = iecTRUE;
        ICS_UINT(current->destination);
        ICS_UINT(current->source);
    }
    ICS_UINT(current->crc);
    iecUINT calculatedCRC = calculateCRC(data, DNP3_HDR_LEN - 2);
    if(current->crc != calculatedCRC) {
        current->hasInvalidChecksum = iecTRUE;
        icsSaveHex(data, octets, o, ICS_HEXDUMP_QUOTED, "DNP3 - invalid dl checksum (0x%04x), (dnp3.datalink.hasInvalidChecksum), ", current->crc);
    }
    current->controlFunction  = current->control & DNP3_DLCTL_FUNCTIONMASK;
    current->controlParameter = current->control & DNP3_DLCTL_PARAMETERMASK;
    if(current->controlFunction == DNP3_DLFCN_FLS ||
       current->controlFunction == DNP3_DLFCN_FSL ||
       current->controlFunction == DNP3_DLFCN_FRL)
        current->hasUnparsedControlFunctions = iecTRUE;
    icsSaveHex(data, octets, o, ICS_HEXDUMP_QUOTED, "DNP3 - well-formed dl, ");
    *po = o;
    return ICS_RESULT_OK;
}

static IcsParseResult parseTransportLayer(Dnp3DataLinkLayer *dataLinkLayer, Dnp3TransportLayer **transportLayer, iecBYTE *data, iecUDINT octets, int *po)
{
    int o = *po;

    if(*transportLayer == NULL) {
        ICS_TMEMORY_P(newTransportLayer, Dnp3TransportLayer);
        *transportLayer = newTransportLayer;
    }
    Dnp3TransportLayer *current = *transportLayer;

    ICS_USINT(current->control);o--;

//    iecUINT sequence = (current->control & DNP3_TLCTL_SEQUENCEMASK);
//    if(sequence != current->sequence + 1) {
//      current->hasSequenceError++;
//      icsSaveHex(data, octets, o+1, ICS_HEXDUMP_QUOTED, "DNP3 - invalid tl sequence %d, (dnp3.transport.hasSequenceError), ", sequence);
//    }
    current->sequence++;

    iecBOOL first = ((current->control & DNP3_TLCTL_FIRST) == DNP3_TLCTL_FIRST);
    current->hasFirstFragment |= first;
    iecBOOL last  = ((current->control & DNP3_TLCTL_FINAL)  == DNP3_TLCTL_FINAL);
    current->hasLastFragment |= last;

    iecUDINT dllLength = dataLinkLayer->length - 5;
    ICS_SMEMORY(fragment, iecBYTE, dllLength);

    iecINT   chunkIdx = 0;
    iecUDINT fragmentSize = 0;
    while(dllLength > 0) {
        iecINT chunkSize = ICS_MIN(dllLength, DNP3_MAX_CHUNK_SIZE);
        iecBYTE *chunk = data + o;
        iecINT adj = !chunkIdx++ ? 1 : 0;
        memcpy(fragment, chunk + adj, chunkSize - adj);
        fragmentSize += chunkSize - adj;
        iecUDINT calculatedCRC = calculateCRC(chunk, chunkSize);
        o += chunkSize;
        chunk += chunkSize - adj;
        ICS_UINT(iecUDINT crc);
        if(crc != calculatedCRC) {
            current->hasInvalidChecksum = iecTRUE;
            icsSaveHex(data, octets, o, ICS_HEXDUMP_QUOTED, "DNP3 - invalid tl checksum (0x%04x), (dnp3.transport.hasInvalidChecksum), ", crc);
        }
        dllLength -= chunkSize;
    }

    Dnp3TLFragment *currFrag = current->fragment;
    if(first) {
        while(currFrag != NULL) {
            Dnp3TLFragment *next = currFrag->next;
            ICS_FREE(currFrag);
            currFrag = next;
        }
        currFrag = NULL;
    }

    if(currFrag == NULL) {
        ICS_TMEMORY_P(newFragment, Dnp3TLFragment);
        currFrag = current->fragment = newFragment;
    }
    else
    while(currFrag->next != NULL)
        currFrag = currFrag->next;

    currFrag->data   = fragment;
    currFrag->length = fragmentSize;

    if(current->hasLastFragment)
        icsSaveHex(data, octets, o, ICS_HEXDUMP_QUOTED, "DNP3 - well-formed tl, ");

    // save these for use in Application layer
    current->data   = data;
    current->octets = octets;
    current->o      = o;

    *po = o;
    return ICS_RESULT_OK;
}

static IcsParseResult parseApplicationLayer(Dnp3TransportLayer *transportLayer, Dnp3ApplicationLayer **applicationLayer)
{
    if(*applicationLayer == NULL) {
        ICS_TMEMORY_P(newApplicationLayer, Dnp3ApplicationLayer);
        *applicationLayer = newApplicationLayer;
    }
    Dnp3ApplicationLayer *current = *applicationLayer;

    int o = 0;
    iecBYTE *data  = transportLayer->fragment->data;
    iecUINT octets = transportLayer->fragment->length;
    ICS_USINT(current->control);
    if((current->control & DNP3_ALCTL_CONFIRM) == DNP3_ALCTL_CONFIRM)
        current->confirm = iecTRUE;
    if((current->control & DNP3_ALCTL_UNSOLICITED) == DNP3_ALCTL_UNSOLICITED)
        current->unsolicited = iecTRUE;
    ICS_USINT(current->function);
    if(avoidFunc(current->function))
        return ICS_RESULT_FUNCTIONIGNORED;
    char *functionString = reverseLookupFunction(current->function);
    if(functionString == NULL) {
        current->hasInvalidFunction = iecTRUE;
        icsSaveHex(transportLayer->data, transportLayer->octets, transportLayer->o, ICS_HEXDUMP_QUOTED, "DNP3 - invalid al function (0x%02x), ", current->function);
    }
    if(current->function > DNP3_MAX_FUNCTION) {
        ICS_UINT_BE(current->indication);
        if(current->indication > 0)
            icsSaveHex(transportLayer->data, transportLayer->octets, transportLayer->o, ICS_HEXDUMP_QUOTED, "DNP3 - internal al indication (0x%04x), ", current->indication);
    }
    if((octets - o) > 2) {
        ICS_USINT(current->object.type);
        ICS_USINT(current->object.index);
        ICS_USINT(current->object.qualifier);
        icsSaveHex(transportLayer->data, transportLayer->octets, transportLayer->o, ICS_HEXDUMP_QUOTED, "DNP3 - al object (type:%d, index:%d, qualifier:%d), ", current->object.type, current->object.index, current->object.qualifier);
    }

    return ICS_RESULT_OK;
}

IcsParseResult icsParseDnp3(IcsLayer startLayer, IcsMode mode, iecBYTE *data, iecUDINT octets, IcsStack *stack)
{
    ICS_IGNORE(mode);
    if((startLayer & ICS_LAYER_APPLICATION) != ICS_LAYER_APPLICATION)
        return ICS_RESULT_UNSUPPORTEDLAYER;

    if(octets < DNP3_HDR_LEN)
        return ICS_RESULT_SHORT;

    int r, o = 0;

    Dnp3DataLinkLayer *dataLinkLayer = NULL;
    if((r = parseDataLinkLayer(&dataLinkLayer, data, octets, &o)) != ICS_RESULT_OK)
        return r;

    ICS_TMEMORY_P(dnp3, Dnp3);
    dnp3->dataLinkLayer = dataLinkLayer;
    if((r = parseTransportLayer(dnp3->dataLinkLayer, &(dnp3->transportLayer), data, octets, &o)) != ICS_RESULT_OK) {
        icsFreeDnp3(dnp3);
        return r;
    }

    if(dnp3->transportLayer->hasLastFragment) {
        if((r = parseApplicationLayer(dnp3->transportLayer, &(dnp3->applicationLayer))) != ICS_RESULT_OK) {
            icsFreeDnp3(dnp3);
            return r;
        }
    }

    iecSINT transactionKey[16];
    snprintf(transactionKey, sizeof(transactionKey), "%02x:%02x:%02x",
             dnp3->dataLinkLayer->source, dnp3->dataLinkLayer->destination,
             dnp3->dataLinkLayer->controlFunction);

    IcsTransaction *transaction = NULL;
    if(dnp3->dataLinkLayer->isResponse) {
        if((transaction = icsTransactionGet(stack, ICS_PROTO_DNP3, transactionKey)) != NULL) {
            Dnp3 *request = transaction->opaque;
            request->applicationLayer->indication = dnp3->applicationLayer->indication;
            icsTransactionMarkComplete(transaction);
        }
    }
    transaction = icsTransactionNew(stack, ICS_PROTO_DNP3, transactionKey, NULL, 3, iecFALSE);
    transaction->opaque = dnp3;
    icsTransactionMarkComplete(transaction);
    shoveVariables(transaction);
    icsSaveHex(data, octets, o, ICS_HEXDUMP_QUOTED, "DNP3 - fully well-formed (mode %u), ", mode);
    return r;
}

IcsProtocol icsProbeDnp3(IcsLayer startLayer, iecBYTE *data, iecUDINT octets)
{
    if((startLayer & ICS_LAYER_APPLICATION) != ICS_LAYER_APPLICATION)
        return ICS_RESULT_UNSUPPORTEDLAYER;
    IcsProtocol r = ICS_PROTO_DNP3;
    int o = 0;
    Dnp3DataLinkLayer *dataLinkLayer = NULL;
    if((parseDataLinkLayer(&dataLinkLayer, data, octets, &o)) != ICS_RESULT_OK)
        r = ICS_PROTO_NONE;
    ICS_FREE(dataLinkLayer);
    return r;
}

