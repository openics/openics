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

#include "icsmodbus.h"

static IcsNumericAssociation modbusFunctions[] = {
    { MODBUS_FUNC_READCOILS,         "read_coils" },
    { MODBUS_FUNC_READDISCINPUTS,    "read_discrete_inputs" },
    { MODBUS_FUNC_READHOLDREGS,      "read_holding_registers" },
    { MODBUS_FUNC_READINPUTREGS,     "read_input_registers" },
    { MODBUS_FUNC_WRITESINGLECOIL,   "write_single_coil" },
    { MODBUS_FUNC_WRITESINGLEREG,    "write_single_register" },
    { MODBUS_FUNC_READEXCSTATUS,     "read_exception_status" },
    { MODBUS_FUNC_DIAGNOSTIC,        "diagnostic" },
    { MODBUS_FUNC_GETCOMEVTCOUNTER,  "get_comm_event_counter" },
    { MODBUS_FUNC_GETCOMEVTLOG,      "get_comm_event_log" },
    { MODBUS_FUNC_WRITEMULTCOILS,    "write_multiple_coils" },
    { MODBUS_FUNC_WRITEMULTREGS,     "write_multiple_registers" },
    { MODBUS_FUNC_REPORTSLAVEID,     "report_slave_id" },
    { MODBUS_FUNC_READFILERECORD,    "read_file_record" },
    { MODBUS_FUNC_WRITEFILERECORD,   "write_file_record" },
    { MODBUS_FUNC_MASKWRITEREG,      "mask_write_register" },
    { MODBUS_FUNC_READWRITEMULTREGS, "read_write_multiple_registers" },
    { MODBUS_FUNC_READFIFOQUEUE,     "read_fifo_queue" },
    { MODBUS_FUNC_ENCAPIFACETRANS,   "encapsulated_interface_transport" },
    { 0x00, NULL }
};

static IcsNumericAssociation modbusStatuses[] = {
    { MODBUS_STAT_OK,                     "status_ok" },
    { MODBUS_STAT_ILLEGALFUNCTION,        "illegal_function" },
    { MODBUS_STAT_ILLEGALDATAADDRESS,     "illegal_data_address" },
    { MODBUS_STAT_ILLEGALDATAVALUE,       "illegal_data_value" },
    { MODBUS_STAT_SLAVEDEVICEFAILURE,     "slave_device_failure" },
    { MODBUS_STAT_ACKNOWLEDGE,            "acknowledge" },
    { MODBUS_STAT_SLAVEDEVICEBUSY,        "slave_device_busy" },
    { MODBUS_STAT_MEMORYPARITYERROR,      "memory_parity_error" },
    { MODBUS_STAT_GATEWAYPATHUNAVAILABLE, "gateway_path_unavailable" },
    { MODBUS_STAT_GATEWAYUNRESPONSIVE,    "gateway_unresponsive" },
    { 0x00, NULL }
};

static IcsNumericAssociation modbusFunctionClasses[] = {
    { MODBUS_CLASS_PUBLIC, "public_function" },
    { MODBUS_CLASS_USER,   "user_function" },
    { 0x00, NULL }
};

static IcsNumericAssociation modbusFunctionSubtypes[] = {
    { MODBUS_CLSUB_RESERVED,  "reserved_function" },
    { MODBUS_CLSUB_WELLKNOWN, "wellknown_function" },
    { MODBUS_CLSUB_UNUSED,    "notinuse_function" },
    { MODBUS_CLSUB_ENCAP,     "encapsulation_function" },
    { 0x00, NULL }
};

static IcsNumericAssociation modbusDiagnosticCodes[] = {
    { MODBUS_DIAG_GETQUERYDATA,       "get_query_data" },
    { MODBUS_DIAG_RESTART,            "restart_slave" },
    { MODBUS_DIAG_GETDIAGREGISTER,    "get_diag_register" },
    { MODBUS_DIAG_CHGDELIMITER,       "change_delimiter" },
    { MODBUS_DIAG_FORCELISTENMODE,    "force_listen_mode" },
    { MODBUS_DIAG_CLEARCOUNTERS,      "clear_counters" },
    { MODBUS_DIAG_GETBUSMSGCOUNT,     "get_bus_msg_count" },
    { MODBUS_DIAG_GETBUSERRCOUNT,     "get_bus_err_count" },
    { MODBUS_DIAG_GETSLAVEMSGCOUNT,   "get_slave_msg_count" },
    { MODBUS_DIAG_GETSLAVENORSPCOUNT, "get_slave_noresp_count" },
    { MODBUS_DIAG_GETSLAVENAKCOUNT,   "get_slave_nak_count" },
    { MODBUS_DIAG_GETSLAVEBUSYCOUNT,  "get_slave_busy_count" },
    { MODBUS_DIAG_GETBUSOVERRUNCOUNT, "get_bus_overrun_count" },
    { MODBUS_DIAG_CLEAROVERRUNSTATS,  "clear_overrun_stats" },
    { 0x00, NULL }
};

static IcsNumericAssociation modbusMeiCodes[] = {
    { MODBUS_MEI_ENCAPX,         "encapsulation_x" },
    { MODBUS_MEI_ENCAPY,         "encapsulation_y" },
    { MODBUS_MEI_CANOPENREQUEST, "canopen_request" },
    { MODBUS_MEI_READDEVICEINFO, "read_device_info" },
    { 0x00, NULL }
};

static ModbusFunctionRange modbusFunctionRanges[] = {
    { { 0x01, 0x07 }, { 0x0000, 0xffff }, MODBUS_CLASS_PUBLIC, MODBUS_CLSUB_WELLKNOWN },
    { { 0x08, 0x08 }, { 0x0000, 0x0012 }, MODBUS_CLASS_PUBLIC, MODBUS_CLSUB_WELLKNOWN }, // subcode
    { { 0x08, 0x08 }, { 0x0013, 0x0013 }, MODBUS_CLASS_PUBLIC, MODBUS_CLSUB_RESERVED  }, // subcode
    { { 0x08, 0x08 }, { 0x0014, 0x0014 }, MODBUS_CLASS_PUBLIC, MODBUS_CLSUB_WELLKNOWN }, // subcode
    { { 0x08, 0x08 }, { 0x0015, 0xffff }, MODBUS_CLASS_PUBLIC, MODBUS_CLSUB_RESERVED  }, // subcode
    { { 0x09, 0x0a }, { 0x0000, 0xffff }, MODBUS_CLASS_PUBLIC, MODBUS_CLSUB_RESERVED  },
    { { 0x0b, 0x0c }, { 0x0000, 0xffff }, MODBUS_CLASS_PUBLIC, MODBUS_CLSUB_WELLKNOWN },
    { { 0x0d, 0x0e }, { 0x0000, 0xffff }, MODBUS_CLASS_PUBLIC, MODBUS_CLSUB_RESERVED  },
    { { 0x0f, 0x11 }, { 0x0000, 0xffff }, MODBUS_CLASS_PUBLIC, MODBUS_CLSUB_WELLKNOWN },
    { { 0x12, 0x13 }, { 0x0000, 0xffff }, MODBUS_CLASS_PUBLIC, MODBUS_CLSUB_UNUSED    },
    { { 0x14, 0x18 }, { 0x0000, 0xffff }, MODBUS_CLASS_PUBLIC, MODBUS_CLSUB_WELLKNOWN },
    { { 0x19, 0x28 }, { 0x0000, 0xffff }, MODBUS_CLASS_PUBLIC, MODBUS_CLSUB_WELLKNOWN },
    { { 0x29, 0x2a }, { 0x0000, 0xffff }, MODBUS_CLASS_PUBLIC, MODBUS_CLSUB_RESERVED  },
    { { 0x2b, 0x2b }, { 0x0000, 0x000c }, MODBUS_CLASS_PUBLIC, MODBUS_CLSUB_RESERVED  }, // mei
    { { 0x2b, 0x2b }, { 0x000d, 0x000e }, MODBUS_CLASS_PUBLIC, MODBUS_CLSUB_ENCAP     }, // mei
    { { 0x2b, 0x2b }, { 0x000f, 0xffff }, MODBUS_CLASS_PUBLIC, MODBUS_CLSUB_RESERVED  }, // mei
    { { 0x2c, 0x40 }, { 0x0000, 0xffff }, MODBUS_CLASS_PUBLIC, MODBUS_CLSUB_UNUSED    },
    { { 0x41, 0x48 }, { 0x0000, 0xffff }, MODBUS_CLASS_USER,   MODBUS_CLSUB_NONE      },
    { { 0x49, 0x59 }, { 0x0000, 0xffff }, MODBUS_CLASS_PUBLIC, MODBUS_CLSUB_UNUSED    },
    { { 0x5a, 0x5b }, { 0x0000, 0xffff }, MODBUS_CLASS_PUBLIC, MODBUS_CLSUB_RESERVED  },
    { { 0x5c, 0x63 }, { 0x0000, 0xffff }, MODBUS_CLASS_PUBLIC, MODBUS_CLSUB_UNUSED    },
    { { 0x64, 0x6e }, { 0x0000, 0xffff }, MODBUS_CLASS_USER,   MODBUS_CLSUB_NONE      },
    { { 0x6f, 0x7c }, { 0x0000, 0xffff }, MODBUS_CLASS_PUBLIC, MODBUS_CLSUB_UNUSED    },
    { { 0x7d, 0x7f }, { 0x0000, 0xffff }, MODBUS_CLASS_PUBLIC, MODBUS_CLSUB_RESERVED  },
    { { 0x00, 0x00 }, { 0x0000, 0x0000 }, MODBUS_CLASS_NONE,   MODBUS_CLSUB_NONE      }
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
    for(i=0; modbusFunctions[i].name; i++)
        if(modbusFunctions[i].value == code)
            return modbusFunctions[i].name;
    return NULL;
}

static ModbusFunctionClass getFunctionClass(ModbusFunction function)
{
    ModbusFunctionClass class = MODBUS_CLASS_NONE;
    int i;
    for(i=0; modbusFunctionRanges[i].class != MODBUS_CLASS_NONE; i++) {
        if(function < modbusFunctionRanges[i].classRange.start)
            break;
        if(function > modbusFunctionRanges[i].classRange.stop)
            continue;
        class = modbusFunctionRanges[i].class;
        break;
    }
    return class;
}

static ModbusFunctionSubtype getFunctionSubtype(ModbusFunction function, iecUINT subcode)
{
    ModbusFunctionSubtype subtype = MODBUS_CLSUB_NONE;
    int i;
    for(i=0; modbusFunctionRanges[i].class != MODBUS_CLASS_NONE; i++) {
        if(function < modbusFunctionRanges[i].classRange.start)
            break;
        if(function > modbusFunctionRanges[i].classRange.stop)
            continue;
        if(subcode >= modbusFunctionRanges[i].subtypeRange.start && subcode <= modbusFunctionRanges[i].subtypeRange.stop) {
            subtype = modbusFunctionRanges[i].subtype;
            break;
        }
    }
    return subtype;
}

static IcsParseResult parseHeader(ModbusHeader **header, iecBYTE *data, iecUDINT octets, int *po)
{
    int o = *po;
    ICS_TMEMORY_P(current, ModbusHeader);
    *header = current;
    ICS_UINT_BE(current->transactionId);
    ICS_UINT_BE(current->protocolId);
    if(current->protocolId != 0) {
        icsSaveHex(data, octets, o, ICS_HEXDUMP_QUOTED, "MODBUS - invalid proto id (0x%04), ", current->protocolId);
        return ICS_RESULT_INVALID;
    }
    ICS_UINT_BE(current->length);
    if(octets - 6 < current->length) {
        icsSaveHex(data, octets, o, ICS_HEXDUMP_QUOTED, "MODBUS - header too small (need %u have %u), ", (iecUDINT) current->length, octets-6);
        return ICS_RESULT_SHORT;
    }
    ICS_USINT(current->unitId);
    ICS_USINT(current->function);
    if((current->function & MODBUS_FUNC_ERRORMASK) == MODBUS_FUNC_ERRORMASK) {
        icsSaveHex(data, octets, o, ICS_HEXDUMP_QUOTED, "MODBUS - error response (0x%02x), ", current->function);
        current->hasErrorResponse = iecTRUE;
    }
    current->function &= MODBUS_FUNC_MASK;
    if(avoidFunc(current->function))
        return ICS_RESULT_FUNCTIONIGNORED;
    if(reverseLookupFunction(current->function) == NULL) {
        icsSaveHex(data, octets, o, ICS_HEXDUMP_QUOTED, "MODBUS - non-standard function (0x%02x), ", current->function);
        current->hasUnknownFunction = iecTRUE;
    }
    current->functionClass = getFunctionClass(current->function);
    *po = o;

    icsSaveHex(data, octets, o, ICS_HEXDUMP_QUOTED, "MODBUS - well-formed header, ");

    return ICS_RESULT_OK;
}

static IcsParseResult parseData(Modbus *modbus, IcsMode mode, iecBYTE *data, iecUDINT octets, int *po)
{
    int o = *po;

    if(mode == ICS_MODE_RQ) {
        modbus->request.dataOffset = o;
        modbus->request.dataLength = octets - o;
        if(modbus->request.dataLength > 0) {
            ICS_SMEMORY_P(newData, iecUSINT, modbus->request.dataLength);
            modbus->request.data = newData;
            if(data != NULL && newData != NULL)
                memcpy(modbus->request.data, data + modbus->request.dataOffset, modbus->request.dataLength);
        }
    }
    else
    if(mode == ICS_MODE_RS) {
        modbus->response.dataOffset = o;
        modbus->response.dataLength = octets - o;
        if(modbus->response.dataLength > 0) {
            ICS_SMEMORY_P(newData, iecUSINT, modbus->response.dataLength);
            modbus->response.data = newData;
            if(data != NULL && newData != NULL)
                memcpy(modbus->response.data, data + modbus->response.dataOffset, modbus->response.dataLength);
        }
    }
    if(modbus->header->function == MODBUS_FUNC_DIAGNOSTIC) {
        ICS_UINT_BE(modbus->subcode);
        modbus->functionSubtype = getFunctionSubtype(modbus->header->function, modbus->subcode);
        icsSaveHex(data, octets, o, ICS_HEXDUMP_QUOTED, "MODBUS - diagnostic subcode (%u), ", modbus->subcode);
    }
    else
    if(modbus->header->function == MODBUS_FUNC_ENCAPIFACETRANS) {
        ICS_USINT(modbus->mei);
        modbus->functionSubtype = getFunctionSubtype(modbus->header->function, modbus->mei);
        icsSaveHex(data, octets, o, ICS_HEXDUMP_QUOTED, "MODBUS - encapsulation interface mei (%u), ", modbus->mei);
    }
    else
        modbus->functionSubtype = getFunctionSubtype(modbus->header->function, 0);
    *po = o;

    icsSaveHex(data, octets, o, ICS_HEXDUMP_QUOTED, "MODBUS - well-formed data, ");

    return ICS_RESULT_OK;
}

static IcsOpaque *alloc(void)
{
    ICS_TMEMORY(modbus, Modbus);
    return modbus;
}

static void shoveVariables(IcsTransaction *transaction)
{
    if(transaction != NULL) {
        if(transaction->variables != NULL)
            icsFreePredicateHash(transaction->variables);
        Modbus *modbus;
        if((modbus = transaction->opaque) != NULL) {
            if((transaction->variables = icsHashCreate(16, 90, SCHA_DEFAULT)) != NULL) {
                ICS_SHOVENUMBER("modbus.header.function",           modbus->header->function);
                ICS_SHOVENUMBER("modbus.header.functionClass",      modbus->header->functionClass);
                ICS_SHOVENUMBER("modbus.header.functionSubtype",    modbus->functionSubtype);
                ICS_SHOVENUMBER("modbus.header.hasErrorResponse",   modbus->header->hasErrorResponse);
                ICS_SHOVENUMBER("modbus.header.hasUnknownFunction", modbus->header->hasUnknownFunction);
                ICS_SHOVENUMBER("modbus.header.transactionId",      modbus->header->transactionId);
                ICS_SHOVENUMBER("modbus.header.unitId",             modbus->header->unitId);
                ICS_SHOVENUMBER("modbus.response.status",           modbus->status);
                ICS_SHOVENUMBER("modbus.request.subCode",           modbus->subcode);
                if(modbus->header->function == 0x08)
                    ICS_SHOVENUMBER("modbus.request.diagCode",      modbus->subcode);
                ICS_SHOVENUMBER("modbus.request.mei",               modbus->mei);

                if(modbus->request.dataLength > 0 && modbus->request.data != NULL) {
                    ICS_SHOVEDATA("modbus.request.data", modbus->request.data, 1, modbus->request.dataLength);
                }
                if(modbus->response.dataLength > 0 && modbus->response.data != NULL) {
                    ICS_SHOVEDATA("modbus.response.data", modbus->response.data, 1, modbus->response.dataLength);
                }
            }
        }
    }
}

static IcsHash *globals;
iecDINT icsInitializeModbus(char *(*configLoader)(char *name))
{
    ICS_FETCH_CONFIG_NUMBER(configLoader, "libics.MODBUS.transactionmax");
    ICS_FETCH_CONFIG_STRING(configLoader, "libics.MODBUS.avoidfuncs");
    ICS_FETCH_CONFIG_STRING(configLoader, "libics.MODBUS.servertcpports");
    ICS_FETCH_CONFIG_STRING(configLoader, "libics.MODBUS.serverudpports");

    iecUINT transMax;
    if((transMax = icsConfigGetNumber("libics.MODBUS.transactionmax")) != ICS_DEFAULT_MAXTRANS)
        transactionMaxima[ICS_PROTO_MODBUS] = transMax;

    if(globals == NULL) {
        if((globals = icsHashCreate(256, 90, SCHA_DEFAULT)) != NULL) {
            int i;
            for(i=0; modbusFunctions[i].name; i++)
                icsHashSetItem(globals, modbusFunctions[i].name, icsCreatePredicateValue(SPVT_NUMERIC, modbusFunctions[i].value, NULL));
            for(i=0; modbusStatuses[i].name; i++)
                icsHashSetItem(globals, modbusStatuses[i].name, icsCreatePredicateValue(SPVT_NUMERIC, modbusStatuses[i].value, NULL));
            for(i=0; modbusFunctionClasses[i].name; i++)
                icsHashSetItem(globals, modbusFunctionClasses[i].name, icsCreatePredicateValue(SPVT_NUMERIC, modbusFunctionClasses[i].value, NULL));
            for(i=0; modbusFunctionSubtypes[i].name; i++)
                icsHashSetItem(globals, modbusFunctionSubtypes[i].name, icsCreatePredicateValue(SPVT_NUMERIC, modbusFunctionSubtypes[i].value, NULL));
            for(i=0; modbusDiagnosticCodes[i].name; i++)
                icsHashSetItem(globals, modbusDiagnosticCodes[i].name, icsCreatePredicateValue(SPVT_NUMERIC, modbusDiagnosticCodes[i].value, NULL));
            for(i=0; modbusMeiCodes[i].name; i++)
                icsHashSetItem(globals, modbusMeiCodes[i].name, icsCreatePredicateValue(SPVT_NUMERIC, modbusMeiCodes[i].value, NULL));
        }
    }

    if(avoidFuncs == NULL) {
        iecSINT *list = icsConfigGetString("libics.MODBUS.avoidfuncs");
        if(list != NULL)
            avoidFuncs = icsNumberArrayFromCommaList(list, 0, &avoidFuncCount);
    }

    return globals == NULL ? 0 : 1;
}

void icsUninitializeModbus(void)
{
    if(globals != NULL)
        icsFreePredicateHash(globals);
    if(avoidFuncs != NULL)
        ICS_FREE(avoidFuncs);
}

IcsDetectItem *icsMungeModbus(const char *keyword, const char *options)
{
    ICS_TMEMORY(item, IcsDetectItem);
    item->predicate = NULL;
    item->globals   = globals;
    item->constants = icsHashCreate(64, 90, SCHA_DEFAULT);
    item->protocol  = ICS_PROTO_MODBUS;

    if(keyword == NULL || strcmp(keyword, "modbus") == 0)
        item->predicate = icsStrdup(options);
    else
    if(strcmp(keyword, "modbus_func") == 0) {
        IcsPredicateValue *funcs = icsNumberArrayFromKeywordParameters(options, modbusFunctions);
        if(funcs != NULL) {
            icsHashSetItem(item->constants, "sig.functions", funcs);
            item->predicate = icsStrdup(MODBUS_PREDICATE_FUNCTION);
        }
    }
    else
    if(strcmp(keyword, "modbus_unit") == 0) {
        IcsPredicateValue *units = icsNumberArrayFromKeywordParameters(options, NULL);
        if(units != NULL) {
            icsHashSetItem(item->constants, "sig.units", units);
            item->predicate = icsStrdup(MODBUS_PREDICATE_UNITID);
        }
    }
    else
    if(strcmp(keyword, "modbus_stat") == 0) {
        IcsPredicateValue *stats = icsNumberArrayFromKeywordParameters(options, modbusStatuses);
        if(stats != NULL) {
            icsHashSetItem(item->constants, "sig.statuses", stats);
            item->predicate = icsStrdup(MODBUS_PREDICATE_STATUS);
        }
    }
    else
    if(strcmp(keyword, "modbus_class") == 0) {
        IcsPredicateValue *classes = icsNumberArrayFromKeywordParameters(options, modbusFunctionClasses);
        if(classes != NULL) {
            icsHashSetItem(item->constants, "sig.classes", classes);
            item->predicate = icsStrdup(MODBUS_PREDICATE_CLASS);
        }
    }
    else
    if(strcmp(keyword, "modbus_subtype") == 0) {
        IcsPredicateValue *subtypes = icsNumberArrayFromKeywordParameters(options, modbusFunctionSubtypes);
        if(subtypes != NULL) {
            icsHashSetItem(item->constants, "sig.subtypes", subtypes);
            item->predicate = icsStrdup(MODBUS_PREDICATE_SUBTYPE);
        }
    }
    else
    if(strcmp(keyword, "modbus_subcode") == 0) {
        IcsPredicateValue *subcodes = icsNumberArrayFromKeywordParameters(options, NULL);
        if(subcodes != NULL) {
            icsHashSetItem(item->constants, "sig.subcodes", subcodes);
            item->predicate = icsStrdup(MODBUS_PREDICATE_SUBCODE);
        }
    }
    else
    if(strcmp(keyword, "modbus_diag") == 0) {
        IcsPredicateValue *diagcodes = icsNumberArrayFromKeywordParameters(options, modbusDiagnosticCodes);
        if(diagcodes != NULL) {
            icsHashSetItem(item->constants, "sig.diagcodes", diagcodes);
            item->predicate = icsStrdup(MODBUS_PREDICATE_DIAGCODE);
        }
    }
    else
    if(strcmp(keyword, "modbus_mei") == 0) {
        IcsPredicateValue *meicodes = icsNumberArrayFromKeywordParameters(options, modbusMeiCodes);
        if(meicodes != NULL) {
            icsHashSetItem(item->constants, "sig.meicodes", meicodes);
            item->predicate = icsStrdup(MODBUS_PREDICATE_MEICODE);
        }
    }
    return item;
}

void icsFreeModbus(IcsOpaque *p)
{
    Modbus *modbus = p;
    if(modbus != NULL) {
        if(modbus->header != NULL)
            ICS_FREE(modbus->header);
        if(modbus->request.data != NULL)
            ICS_FREE(modbus->request.data);
        if(modbus->response.data != NULL)
            ICS_FREE(modbus->response.data);
        ICS_FREE(modbus);
    }
}

IcsParseResult icsParseModbus(IcsLayer startLayer, IcsMode mode, iecUSINT *data, iecUDINT octets, IcsStack *stack)
{
    if((startLayer & ICS_LAYER_APPLICATION) != ICS_LAYER_APPLICATION)
        return ICS_RESULT_UNSUPPORTEDLAYER;

    IcsTransaction *transaction = NULL;
    iecSINT transactionKey[16];

    int r = ICS_RESULT_OK, o = 0;

    if(mode == ICS_MODE_RQ) {
        ModbusHeader *header;
        if((r = parseHeader(&header, data, octets, &o)) != ICS_RESULT_OK)
            return r;
        snprintf(transactionKey, sizeof(transactionKey), "%04x:%02x:%02x",
                 header->transactionId, header->unitId, header->function);
        if((transaction = icsTransactionNew(stack, ICS_PROTO_MODBUS, transactionKey, alloc, 5, iecFALSE)) != NULL) {
            Modbus *modbus = transaction->opaque;
            modbus->header = header;
            r = parseData(modbus, ICS_MODE_RQ, data, octets, &o);
            shoveVariables(transaction);
        }
    }
    else
    if(mode == ICS_MODE_RS) {
        ModbusHeader *header;
        if((r = parseHeader(&header, data, octets, &o)) != ICS_RESULT_OK)
            return r;
        snprintf(transactionKey, sizeof(transactionKey), "%04x:%02x:%02x",
                 header->transactionId, header->unitId, header->function);
        if(header->hasErrorResponse) {
            ICS_USINT(ModbusStatus status);
            if((transaction = icsTransactionGet(stack, ICS_PROTO_MODBUS, transactionKey)) != NULL) {
                Modbus *modbus = transaction->opaque;
                modbus->status = status;
                shoveVariables(transaction);
                icsTransactionMarkComplete(transaction);
                ICS_FREE(header);
            }
            else
            if((transaction = icsTransactionNew(stack, ICS_PROTO_MODBUS, transactionKey, alloc, 0, iecFALSE)) != NULL) {
                Modbus *modbus = transaction->opaque;
                modbus->header = header;
                modbus->status = status;
                shoveVariables(transaction);
                icsTransactionMarkComplete(transaction);
            }
        }
        else
        if((transaction = icsTransactionNew(stack, ICS_PROTO_MODBUS, transactionKey, alloc, 0, iecFALSE)) != NULL) {
            Modbus *modbus = transaction->opaque;
            modbus->header = header;
            r = parseData(modbus, ICS_MODE_RS, data, octets, &o);
            shoveVariables(transaction);
            icsTransactionMarkComplete(transaction);
        }
    }

    icsSaveHex(data, octets, o, ICS_HEXDUMP_QUOTED, "MODBUS - fully well-formed (%u), ", mode);

    return ICS_RESULT_OK;
}

IcsProtocol icsProbeModbus(IcsLayer startLayer, iecUSINT *data, iecUDINT octets)
{
    if((startLayer & ICS_LAYER_APPLICATION) != ICS_LAYER_APPLICATION)
        return ICS_RESULT_UNSUPPORTEDLAYER;
    int o = 0;
    ModbusHeader *header;
    int r = parseHeader(&header, data, octets, &o);
    if(header != NULL)
        ICS_FREE(header);
    return r == ICS_RESULT_OK ? ICS_PROTO_MODBUS : ICS_PROTO_NONE;
}
