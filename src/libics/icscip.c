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

#include "icscip.h"

static IcsNumericAssociation cipServices[] = {
    { CIP_SRV_GETATTRALL,   "get_attr_all" },
    { CIP_SRV_SETATTRALL,   "set_attr_all" },
    { CIP_SRV_GETATTRLIST,  "get_attr_list" },
    { CIP_SRV_SETATTRLIST,  "set_attr_list" },
    { CIP_SRV_RESET,        "reset" },
    { CIP_SRV_START,        "start" },
    { CIP_SRV_STOP,         "stop" },
    { CIP_SRV_CREATE,       "create" },
    { CIP_SRV_DELETE,       "delete" },
    { CIP_SRV_MSP,          "msp" },
    { CIP_SRV_APPLYATTR,    "apply_attr" },
    { CIP_SRV_GETATTR,      "get_attr" },
    { CIP_SRV_SETATTR,      "set_attr" },
    { CIP_SRV_FINDNEXTOBJ,  "find_next_obj" },
    { CIP_SRV_RESTORE,      "restore" },
    { CIP_SRV_SAVE,         "save" },
    { CIP_SRV_NOOP,         "noop" },
    { CIP_SRV_GETMEMBER,    "get_member" },
    { CIP_SRV_SETMEMBER,    "set_member" },
    { CIP_SRV_INSERTMEMBER, "insert_member" },
    { CIP_SRV_REMOVEMEMBER, "remove_member" },
    { CIP_SRV_GROUPSYNC,    "group_sync" },
    { CIP_SRV_KICKTIMER,    "kick_timer" },
    { CIP_SRV_OPENCONN,     "open_conn" },
    { CIP_SRV_CLOSECONN,    "close_conn" },
    { CIP_SRV_STOPCONN,     "stop_conn" },
    { CIP_SRV_CHANGESTART,  "change_start" },
    { CIP_SRV_GETSTATUS,    "get_status" },
    { CIP_SRV_CHANGEDONE,   "change_done" },
    { CIP_SRV_AUDITCHANGE,  "audit_change" },
    { CIP_SRV_FWDOPEN,      "forward_open" },
    { CIP_SRV_LARGEFWDOPEN, "large_forward_open" },
    { CIP_SRV_GETCONNOWNER, "get_conn_owner" },
    { 0x00, NULL }
};

static IcsNumericAssociation cipStatuses[] = {
    { CIP_STAT_SUCCESS,           "success" },
    { CIP_STAT_FAILURE,           "failure" },
    { CIP_STAT_NORESOURCE,        "no_resource" },
    { CIP_STAT_BADDATA,           "bad_data" },
    { CIP_STAT_BADPATH,           "bad_path" },
    { CIP_STAT_BADCLASSINST,      "bad_class_instance" },
    { CIP_STAT_PARTIALDATA,       "partial_data" },
    { CIP_STAT_CONNLOST,          "conn_lost" },
    { CIP_STAT_BADSERVICE,        "bad_service" },
    { CIP_STAT_BADATTRDATA,       "bad_attr_data" },
    { CIP_STAT_ATTRLISTERROR,     "attr_list_error" },
    { CIP_STAT_ALREADYINMODE,     "already_in_mode" },
    { CIP_STAT_BADOBJMODE,        "bad_obj_mode" },
    { CIP_STAT_OBJEXISTS,         "obj_exists" },
    { CIP_STAT_ATTRNOTSETTABLE,   "attr_not_settable" },
    { CIP_STAT_PERMISSIONDENIED,  "permission_denied" },
    { CIP_STAT_DEVINWRONGSTATE,   "dev_in_wrong_state" },
    { CIP_STAT_REPLYTOOLARGE,     "reply_too_large" },
    { CIP_STAT_FRAGPRIMITIVE,     "frag_primitive" },
    { CIP_STAT_CONFIGTOOSMALL,    "config_too_small" },
    { CIP_STAT_UNDEFINEDATTR,     "undefined_attr" },
    { CIP_STAT_CONFIGTOOBIG,      "config_too_big" },
    { CIP_STAT_OBJDOESNOTEXIST,   "obj_does_not_exist" },
    { CIP_STAT_NOFRAG,            "no_frag" },
    { CIP_STAT_DATANOTSAVED,      "data_not_saved" },
    { CIP_STAT_DATAWRITEFAILURE,  "data_write_failure" },
    { CIP_STAT_REQUESTTOOLARGE,   "request_too_large" },
    { CIP_STAT_RESPONSETOOLARGE,  "response_too_large" },
    { CIP_STAT_MISSINGLISTDATA,   "missing_list_data" },
    { CIP_STAT_INVALIDLISTSTATUS, "invalid_list_status" },
    { CIP_STAT_SERVICEERROR,      "service_error" },
    { CIP_STAT_CONNFAILURE,       "conn_failure" },
    { CIP_STAT_INVALIDPARAMETER,  "invalid_parameter" },
    { CIP_STAT_WRITEONCEFAILURE,  "write_once_failure" },
    { CIP_STAT_INVALIDREPLY,      "invalid_reply" },
    { CIP_STAT_BUFFEROVERFLOW,    "buffer_overflow" },
    { CIP_STAT_MESSAGEFORMAT,     "message_format" },
    { CIP_STAT_BADKEYINPATH,      "bad_key_in_path" },
    { CIP_STAT_BADPATHSIZE,       "bad_path_size" },
    { CIP_STAT_UNEXPECTEDATTR,    "unexpected_attr" },
    { CIP_STAT_INVALIDMEMBER,     "invalid_member" },
    { CIP_STAT_MEMBERNOTSETTABLE, "member_not_settable" },
    { CIP_STAT_G2SERVERFAILURE,   "g2_server_failure" },
    { CIP_STAT_UNKNOWNMBERROR,    "unknown_mb_error" },
    { CIP_STAT_STILLPROCESSING,   "still processing" },
    { 0x00, NULL }
};

static IcsNumericAssociation cipObjectIDs[] = {
    { CIP_OID_IDENTITY,             "identity" },
    { CIP_OID_MSGROUTER,            "message_router" },
    { CIP_OID_DEVICENET,            "devicenet" },
    { CIP_OID_ASSEMBLY,             "assembly" },
    { CIP_OID_CONNECTION,           "connection" },
    { CIP_OID_CONNMANAGER,          "connection_manager" },
    { CIP_OID_REGISTER,             "register" },
    { CIP_OID_DISCINPPOINT,         "discrete_input_point" },
    { CIP_OID_DISCOUTPOINT,         "discrete_output_point" },
    { CIP_OID_ANAINPPOINT,          "analog_input_point" },
    { CIP_OID_ANAOUTPOINT,          "analog_output_point" },
    { CIP_OID_PRESSENSING,          "presence_sensing" },
    { CIP_OID_PARAMETER,            "parameter" },
    { CIP_OID_PARMGROUP,            "parameter_group" },
    { CIP_OID_GROUP,                "group" },
    { CIP_OID_DISCINPGROUP,         "discrete_input_group" },
    { CIP_OID_DISCOUTGROUP,         "discrete_output_group" },
    { CIP_OID_DISCGROUP,            "discrete_group" },
    { CIP_OID_ANAINPGROUP,          "analog_input_group" },
    { CIP_OID_ANAOUTGROUP,          "analog_output_group" },
    { CIP_OID_ANAGROUP,             "analog_group" },
    { CIP_OID_POSSENSOR,            "position_sensor" },
    { CIP_OID_POSCONTSUPER,         "position_controller_supervisor" },
    { CIP_OID_POSCONTROLLER,        "position_controller" },
    { CIP_OID_BLOCKSEQENCER,        "block_sequencer" },
    { CIP_OID_COMMANDBLOCK,         "command_block" },
    { CIP_OID_MOTORDATA,            "motor_data" },
    { CIP_OID_CONTSUPER,            "control_supervisor" },
    { CIP_OID_ACDCDRIVE,            "acdc_drive" },
    { CIP_OID_ACKHANDLER,           "acknowledge_handler" },
    { CIP_OID_OVERLOAD,             "overload" },
    { CIP_OID_SOFTSTART,            "softstart" },
    { CIP_OID_SELECTION,            "selection" },
    { CIP_OID_DEVICESUPER,          "s_device_supervisor" },
    { CIP_OID_SANASENSOR,           "s_analog_sensor" },
    { CIP_OID_SANAACTUATOR,         "s_analog_actuator" },
    { CIP_OID_SSINGLESTAGECONT,     "s_single_stage_controller" },
    { CIP_OID_SGASCALIBRATION,      "s_gas_calibration" },
    { CIP_OID_TRIPPOINT,            "trip_point" },
    { CIP_OID_DRIVEDATA,            "drive_data" }, // n/a?
    { CIP_OID_FILE,                 "file" },
    { CIP_OID_SPARTPRESSURE,        "s_partial_pressure" },
    { CIP_OID_SAFESUPER,            "safety_supervisor" },
    { CIP_OID_SAFEVALIDATOR,        "safety_validator" },
    { CIP_OID_SAFEDISCOUTPOINT,     "safety_discrete_output_point" },
    { CIP_OID_SAFEDISCOUTGROUP,     "safety_discrete_output_group" },
    { CIP_OID_SAFEDISCINPPOINT,     "safety_discrete_input_point" },
    { CIP_OID_SAFEDISCINPGROUP,     "safety_discrete_input_group" },
    { CIP_OID_SAFEDUALCHANOUTPUT,   "safety_dual_channel_output" },
    { CIP_OID_SSENSORCALIBRATION,   "s_sensor_calibration" },
    { CIP_OID_EVENTLOG,             "event_log" },
    { CIP_OID_MOTIONAXIS,           "motion_axis" },
    { CIP_OID_TIMESYNC,             "time_sync" },
    { CIP_OID_MODBUS,               "modbus" },
    { CIP_OID_CONTNET,              "controlnet" },
    { CIP_OID_CONTNETKEEPER,        "controlnet_keeper" },
    { CIP_OID_CONTNETSCHED,         "controlnet_scheduling" },
    { CIP_OID_CONNCONFIG,           "connection_configuration" },
    { CIP_OID_PORT,                 "port" },
    { CIP_OID_TCPIPXFACE,           "tcpip_interface" },
    { CIP_OID_ETHERLINK,            "ethernet_link" },
    { CIP_OID_COMPONETLINK,         "componet_link" },
    { CIP_OID_COMPONETREPEATER,     "componet_repeater" },
    { 0x00, NULL }
};

static IcsNumericAssociation cipSegmentTypes[] = {
    { CIP_SEGT_PORT,     "port_segment" },
    { CIP_SEGT_LOGICAL,  "logical_segment" },
    { CIP_SEGT_NETWORK,  "network_segment" },
    { CIP_SEGT_SYMBOLIC, "symbolic_segment" },
    { CIP_SEGT_DATA,     "data_segment" },
    { CIP_SEGT_CTYPE,    "ctype_segment" },
    { CIP_SEGT_ETYPE,    "etype_segment" },
    { 0x00, NULL }
};

static IcsNumericAssociation cipLogicalSegmentTypes[] = {
    { CIP_SEGLT_CLASSID,   "class_id" },
    { CIP_SEGLT_INSTID,    "instance_id" },
    { CIP_SEGLT_MEMBERID,  "member_id" },
    { CIP_SEGLT_CONNPOINT, "connection_point" },
    { CIP_SEGLT_ATTRID,    "attribute_id" },
    { CIP_SEGLT_SPECIAL,   "special" },
    { CIP_SEGLT_SERVICEID, "service_id" },
    { 0x00, NULL }
};

static IcsNumericAssociation cipNetworkSegmentTypes[] = {
    { CIP_SEGNT_SCHEDULE,  "schedule" },
    { CIP_SEGNT_FIXEDTAG,  "fixed_tag" },
    { CIP_SEGNT_PRODINHIB, "prod_inhibit" },
    { CIP_SEGNT_SAFETY,    "safety" },
    { CIP_SEGNT_EXTENDED,  "extended" },
    { 0x00, NULL }
};

static IcsNumericAssociation cipDataSegmentTypes[] = {
    { CIP_SEGDT_SIMPLE, "simple" },
    { CIP_SEGDT_ANSIX,  "ansix" },
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

static char *reverseLookupService(iecUSINT code)
{
    int i;
    for(i=0; cipServices[i].name; i++)
        if(cipServices[i].value == code)
            return cipServices[i].name;
    return NULL;
}

static void shoveVariables(IcsTransaction *transaction)
{
    if(transaction != NULL) {
        if(transaction->variables != NULL)
            icsFreePredicateHash(transaction->variables);
        Cip *cip;
        if((cip = transaction->opaque) != NULL) {
            if((transaction->variables = icsHashCreate(16, 90, SCHA_DEFAULT)) != NULL) {
                ICS_SHOVENUMBER("cip.header.service", cip->header->service);
                CipSegment *path = cip->rqPath;
                while(path != NULL) {
                    ICS_SHOVENUMBER("cip.request.path.type", path->type);
                    switch(path->type) {
                        case CIP_SEGT_PORT: {
                            CipPortSegment *port = path->opaque;
                            ICS_SHOVENUMBER("cip.request.path.hasPortSegment", 1);
                            ICS_SHOVENUMBER("cip.request.path.port.portId", port->portId);
                            if(port->linkAddressSize > 0 && port->linkAddress != NULL) {
                                ICS_SHOVEDATA("cip.request.path.port.linkAddress", port->linkAddress, 1, port->linkAddressSize);
                            }
                        } break;
                        case CIP_SEGT_LOGICAL: {
                            CipLogicalSegment *logical = path->opaque;
                            ICS_SHOVENUMBER("cip.request.path.hasLogicalSegment", 1);
                            ICS_SHOVENUMBER("cip.request.path.logical.type", logical->type);
                            switch(logical->type) {
                                case CIP_SEGLT_CLASSID: {
                                    ICS_SHOVENUMBER("cip.request.path.logical.classId", logical->value);
                                } break;
                                case CIP_SEGLT_INSTID: {
                                    ICS_SHOVENUMBER("cip.request.path.logical.instanceId", logical->value);
                                } break;
                                case CIP_SEGLT_MEMBERID: {
                                    ICS_SHOVENUMBER("cip.request.path.logical.memberId", logical->value);
                                } break;
                                case CIP_SEGLT_CONNPOINT: {
                                    ICS_SHOVENUMBER("cip.request.path.logical.connectionPoint", logical->value);
                                } break;
                                case CIP_SEGLT_ATTRID: {
                                    ICS_SHOVENUMBER("cip.request.path.logical.attributeId", logical->value);
                                }
                                case CIP_SEGLT_SPECIAL: {
                                    if(logical->ekey != NULL) {
                                        ICS_SHOVENUMBER("cip.request.path.logical.ekey.deviceType",   logical->ekey->deviceType);
                                        ICS_SHOVENUMBER("cip.request.path.logical.ekey.isCompatible", logical->ekey->isCompatible);
                                        ICS_SHOVENUMBER("cip.request.path.logical.ekey.majorRev",     logical->ekey->majorRev);
                                        ICS_SHOVENUMBER("cip.request.path.logical.ekey.minorRev",     logical->ekey->minorRev);
                                        ICS_SHOVENUMBER("cip.request.path.logical.ekey.productCode",  logical->ekey->productCode);
                                        ICS_SHOVENUMBER("cip.request.path.logical.ekey.vendorId",     logical->ekey->vendorId);
                                    }
                                }
                                case CIP_SEGLT_SERVICEID: {
                                    ICS_SHOVENUMBER("cip.request.path.logical.serviceId", logical->serviceId);
                                }
                                default: break;
                            }
                        } break;
                        case CIP_SEGT_NETWORK: {
                            CipNetworkSegment *network = path->opaque;
                            ICS_SHOVENUMBER("cip.request.path.hasNetworkSegment", 1);
                            ICS_SHOVENUMBER("cip.request.path.network.type", network->type);
                            ICS_SHOVENUMBER("cip.request.path.network.hasUnknownType",  network->isUnknownType);
                            switch(network->type) {
                                case CIP_SEGNT_PRODINHIB: {
                                    ICS_SHOVENUMBER("cip.request.path.network.inhibitTime", network->inhibitTime);
                                } break;
                                case CIP_SEGNT_EXTENDED: {
                                    ICS_SHOVEDATA("cip.request.path.network.extendedData", network->extendedData, 2, network->length);
                                    ICS_SHOVENUMBER("cip.request.path.network.extendedType", network->extendedSubType);
                                } break;
                                case CIP_SEGNT_SCHEDULE: {
                                    ICS_SHOVENUMBER("cip.request.path.network.hasScheduleType", 1);
                                } break;
                                case CIP_SEGNT_FIXEDTAG:  {
                                    ICS_SHOVENUMBER("cip.request.path.network.hasFixedTagType", 1);
                                } break;
                                case CIP_SEGNT_SAFETY:  {
                                    ICS_SHOVENUMBER("cip.request.path.network.hasSafetyType", 1);
                                } break;
                                default: break;
                            }
                        } break;
                        case CIP_SEGT_SYMBOLIC: {
                            CipSymbolicSegment *symbolic = path->opaque;
                            ICS_SHOVENUMBER("cip.request.path.hasSymbolicSegment", 1);
                            if(symbolic->asciiString != NULL) {
                                ICS_SHOVESTRING("cip.request.path.symbolic.asciiString", symbolic->asciiString);
                            }
                            else
                            if(symbolic->isUnknownXFormat || symbolic->isUnknownXType) {
                                ICS_SHOVENUMBER("cip.request.path.symbolic.hasInvalidExtendedSymbol", 1);
                            }
                            else {
                                if(symbolic->isNumeric) {
                                    ICS_SHOVENUMBER("cip.request.path.symbolic.numeric", symbolic->numericSymbol);
                                }
                                if(symbolic->doubleString != NULL) {
                                    ICS_SHOVEDATA("cip.request.path.symbolic.doubleString", symbolic->doubleString, 2, symbolic->length);
                                }
                                if(symbolic->tripleString != NULL) {
                                    ICS_SHOVEDATA("cip.request.path.symbolic.tripleString", symbolic->tripleString, 4, symbolic->length);
                                }
                            }
                        } break;
                        case CIP_SEGT_DATA: {
                            CipDataSegment *data = path->opaque;
                            ICS_SHOVENUMBER("cip.request.path.hasDataSegment", 1);
                            if(data->ansiData != NULL) {
                                ICS_SHOVEDATA("cip.request.path.data.ansi", data->ansiData, 1, data->length);
                            }
                            if(data->simpleData != NULL) {
                                ICS_SHOVEDATA("cip.request.path.data.simple", data->simpleData, 2, data->length);
                            }
                        } break;
                        case CIP_SEGT_CTYPE: {
                            ICS_SHOVENUMBER("cip.request.path.hasCTypeSegment", 1);
                        } break;
                        case CIP_SEGT_ETYPE: {
                            ICS_SHOVENUMBER("cip.request.path.hasETypeSegment", 1);
                        } break;
                        default: break;
                    }
                    path = path->next;
                }
                if(cip->rqData != NULL) {
                    if(cip->rqData->length > 0 && cip->rqData->data != NULL) {
                        // only first one in chain for now
                        ICS_SHOVEDATA("cip.request.data", cip->rqData->data, 1, cip->rqData->length);
                    }
                }
                if(cip->rsStatus != NULL) {
                    ICS_SHOVENUMBER("cip.response.status", cip->rsStatus->status);
                    if(cip->rsStatus->addlLength > 0 && cip->rsStatus->addlStatus != NULL) {
                        ICS_SHOVENUMBER("cip.response.hasAddlStatus", 1);
                        ICS_SHOVEDATA("cip.response.addlStatus", cip->rsStatus->addlStatus, 2, cip->rsStatus->addlLength);
                    }
                }
                if(cip->rsData != NULL) {
                    if(cip->rsData->length > 0 && cip->rsData->data != NULL) {
                        // only first one in chain for now
                        ICS_SHOVEDATA("cip.response.data", cip->rsData->data, 1, cip->rsData->length);
                    }
                }
            }
        }
    }
}

static IcsParseResult parsePortSegment(iecBOOL padded, CipPortSegment **portSegment, iecBYTE *data, iecUDINT octets, int *po)
{
    int o = *po;
    ICS_TMEMORY_P(current, CipPortSegment);
    *portSegment = current;
    ICS_USINT(CipSegmentType segment);
    current->portId = segment & CIP_SEGO_PORTIDMASK;
    if(current->portId == CIP_SEGO_PORTIDMASK) {
        ICS_UINT(current->portId);
    }
    current->linkAddressSize = 1;
    if((segment & CIP_SEGO_PORTBIGADDR) == CIP_SEGO_PORTBIGADDR) {
        ICS_USINT(current->linkAddressSize);
    }
    ICS_USINTS(current->linkAddress, current->linkAddressSize);
    if(padded && (o - *po) % 2)
        o++;
    *po = o;
    return ICS_RESULT_OK;
}

static IcsParseResult parseLogicalSegment(iecBOOL padded, CipLogicalSegment **logicalSegment, iecBYTE *data, iecUDINT octets, int *po)
{
    int o = *po;
    ICS_TMEMORY_P(current, CipLogicalSegment);
    *logicalSegment = current;
    ICS_USINT(CipSegmentType segment);
    current->type = segment & CIP_SEGLT_MASK;
    current->format = segment & CIP_SEGLF_MASK;
    if(current->type == CIP_SEGLT_SPECIAL) {
        if(current->format != CIP_SEGLF_EKEY)
            return ICS_RESULT_INVALIDCODING;
        ICS_USINT(iecUSINT keyFormat);
        if(keyFormat != 4)
            return ICS_RESULT_INVALIDCODING;
        ICS_TMEMORY_P(ekey, CipElectronicKey);
        current->ekey = ekey;
        ICS_UINT(current->ekey->vendorId);
        ICS_UINT(current->ekey->deviceType);
        ICS_UINT(current->ekey->productCode);
        ICS_USINT(current->ekey->majorRev);
        if((current->ekey->majorRev & 0x80) == 0x80) {
            current->ekey->isCompatible = 1;
            current->ekey->majorRev &= 0x7f;
        }
        ICS_USINT(current->ekey->minorRev);
    }
    else
    if(current->type == CIP_SEGLT_SERVICEID) {
        if(current->format != CIP_SEGLF_SRVID)
            return ICS_RESULT_INVALIDCONTEXT;
        if(padded) {
            ICS_USINT(current->padByte);
        }
        ICS_USINT(current->serviceId);
    }
    else {
        if(current->format == CIP_SEGLF_8BIT) {
            ICS_USINT(current->value);
        }
        else
        if(current->format == CIP_SEGLF_16BIT) {
            if(padded) {
                ICS_USINT(current->padByte);
            }
            ICS_UINT(current->value);
        }
        else
        if(current->format == CIP_SEGLF_32BIT) {
            if(current->type != CIP_SEGLT_INSTID && current->type != CIP_SEGLT_CONNPOINT)
                return ICS_RESULT_INVALIDCONTEXT;
            if(padded) {
                ICS_USINT(current->padByte);
            }
            ICS_UDINT(current->value);
        }
        else
            return ICS_RESULT_INVALIDCODING;
    }
    *po = o;
    return ICS_RESULT_OK;
}

static IcsParseResult parseNetworkSegment(iecBOOL padded, CipNetworkSegment **networkSegment, iecBYTE *data, iecUDINT octets, int *po)
{
    ICS_IGNORE(padded);
    int o = *po;
    ICS_TMEMORY_P(current, CipNetworkSegment)
    *networkSegment = current;
    ICS_USINT(CipSegmentType segment);
    current->type = segment & CIP_SEGNT_MASK;
    if(current->type == CIP_SEGNT_SCHEDULE) {
        return ICS_RESULT_NOTIMPLEMENTED;
    }
    else
    if(current->type == CIP_SEGNT_FIXEDTAG) {
        return ICS_RESULT_NOTIMPLEMENTED;
    }
    else
    if(current->type == CIP_SEGNT_SAFETY) {
        return ICS_RESULT_NOTIMPLEMENTED;
    }
    else
    if(current->type == CIP_SEGNT_PRODINHIB) {
        ICS_USINT(current->inhibitTime);
    }
    if(current->type == CIP_SEGNT_EXTENDED) {
        ICS_USINT(current->length);
        ICS_UINT(current->extendedSubType);
        ICS_UINTS(current->extendedData, current->length);
    }
    else
        current->isUnknownType = 1;
    *po = o;
    return ICS_RESULT_OK;
}

static IcsParseResult parseSymbolicSegment(iecBOOL padded, CipSymbolicSegment **symbolicSegment, iecBYTE *data, iecUDINT octets, int *po)
{
    ICS_IGNORE(padded);
    int o = *po;
    ICS_TMEMORY_P(current, CipSymbolicSegment);
    *symbolicSegment = current;
    ICS_USINT(CipSegmentType segment);
    current->length = segment & CIP_SEGO_SYMSIZEMASK;
    if(current->length > 0) {
        ICS_SINTS(current->asciiString, current->length);
        if(current->length % 2) {
            ICS_USINT(current->padByte);
        }
    }
    else {
        ICS_USINT(iecUSINT x);
        CipSegmentXStringType xFormat =  x & CIP_SEGXS_MASK;
        current->length = x & CIP_SEGXST_MASK;
        if(xFormat == CIP_SEGXS_DOUBLES) {
            ICS_STRING2(current->doubleString, current->length);
        }
        else
        if(xFormat == CIP_SEGXS_TRIPLES) {
            ICS_STRING3(current->tripleString, current->length);
        }
        else
        if(xFormat == CIP_SEGXS_NUMERIC) {
            current->isNumeric = 1;
            CipSegmentXStringNType xType = x & CIP_SEGXST_MASK;
            if(xType == CIP_SEGXST_BYTE) {
                ICS_USINT(current->numericSymbol);
            }
            else
            if(xType == CIP_SEGXST_WORD) {
                ICS_UINT(current->numericSymbol);
            }
            else
            if(xType == CIP_SEGXST_DWORD) {
                ICS_UDINT(current->numericSymbol);
            }
            else
                current->isUnknownXType = 1;
        }
        else
            current->isUnknownXFormat = 1;
    }
    *po = o;
    return ICS_RESULT_OK;
}

static IcsParseResult parseDataSegment(iecBOOL padded, CipDataSegment **dataSegment, iecBYTE *data, iecUDINT octets, int *po)
{
    int o = *po;
    ICS_TMEMORY_P(current, CipDataSegment);
    *dataSegment = current;
    ICS_USINT(CipSegmentType segment);
    if((segment & CIP_SEGT_MASK) != CIP_SEGT_DATA)
        return ICS_RESULT_INVALIDCONTEXT;
    ICS_USINT(current->length);
    current->type = segment & CIP_SEGDT_MASK;
    if(current->type == CIP_SEGDT_SIMPLE) {
        ICS_UINTS(current->simpleData, current->length);
    }
    else
    if(current->type == CIP_SEGDT_ANSIX) {
        ICS_USINTS(current->ansiData, current->length);
    }
    else
        return ICS_RESULT_UNKNOWNITEM;
    if(padded && (o - *po) % 2)
        o++;
    *po = o;
    return ICS_RESULT_OK;
}

static IcsParseResult parseCTypeSegment(iecBOOL padded, CipCTypeSegment **ctypeSegment, iecBYTE *data, iecUDINT octets, int *po)
{
    ICS_IGNORE(padded);
    int o = *po;
    ICS_TMEMORY_P(current, CipCTypeSegment);
    *ctypeSegment = current;
    ICS_IGNORE(current);
    ICS_USINT(CipSegmentType segment);
    ICS_IGNORE(segment);
    *po = o;
    return ICS_RESULT_OK;
}

static IcsParseResult parseETypeSegment(iecBOOL padded, CipETypeSegment **etypeSegment, iecBYTE *data, iecUDINT octets, int *po)
{
    ICS_IGNORE(padded);
    int o = *po;
    ICS_TMEMORY_P(current, CipETypeSegment);
    *etypeSegment = current;
    ICS_IGNORE(current);
    ICS_USINT(CipSegmentType segment);
    ICS_IGNORE(segment);
    *po = o;
    return ICS_RESULT_OK;
}

static void freeSegment(CipSegmentType type, IcsOpaque *opaque)
{
    switch(type) {
        case CIP_SEGT_PORT: {
            CipPortSegment *portSegment = opaque;
            ICS_FREE(portSegment->linkAddress);
        } break;
        case CIP_SEGT_LOGICAL: {
            CipLogicalSegment *logicalSegment = opaque;
            ICS_FREE(logicalSegment->ekey);
        } break;
        case CIP_SEGT_NETWORK: {
            CipNetworkSegment *networkSegment = opaque;
            ICS_FREE(networkSegment->extendedData);
        } break;
        case CIP_SEGT_SYMBOLIC: {
            CipSymbolicSegment *symbolicSegment = opaque;
            ICS_FREE(symbolicSegment->asciiString);
            ICS_FREE(symbolicSegment->doubleString);
            ICS_FREE(symbolicSegment->tripleString);
        } break;
        case CIP_SEGT_DATA: {
            CipDataSegment *dataSegment = opaque;
            ICS_FREE(dataSegment->ansiData);
            ICS_FREE(dataSegment->simpleData);
        } break;
        case CIP_SEGT_CTYPE: {
        } break;
        case CIP_SEGT_ETYPE: {
        } break;
        default: break;
    }
    ICS_FREE(opaque);
}

static IcsParseResult parseSegments(iecBOOL padded, CipSegment **segmentBase, iecBYTE *data, iecUDINT octets, int *po)
{
    int r, o = *po;
    ICS_USINT(iecUSINT pathSize);
    iecUSINT usi;
    CipSegment *current = NULL;
    for(usi = 0; usi < pathSize; usi++) {
        IcsOpaque *opaque = NULL;
        ICS_USINT(CipSegmentType type);o--;
        type &= CIP_SEGT_MASK;
        switch(type) {
            case CIP_SEGT_PORT: {
                CipPortSegment *portSegment;
                if((r = parsePortSegment(padded, &portSegment, data, octets, &o)) != ICS_RESULT_OK)
                    return r;
                opaque = portSegment;
                icsSaveHex(data, octets, octets, ICS_HEXDUMP_QUOTED, "CIP - port segment, ");
            } break;
            case CIP_SEGT_LOGICAL: {
                CipLogicalSegment *logicalSegment;
                if((r = parseLogicalSegment(padded, &logicalSegment, data, octets, &o)) != ICS_RESULT_OK)
                    return r;
                opaque = logicalSegment;
                icsSaveHex(data, octets, octets, ICS_HEXDUMP_QUOTED, "CIP - logical segment, ");
            } break;
            case CIP_SEGT_NETWORK: {
                CipNetworkSegment *networkSegment;
                if((r = parseNetworkSegment(padded, &networkSegment, data, octets, &o)) != ICS_RESULT_OK)
                    return r;
                opaque = networkSegment;
                icsSaveHex(data, octets, octets, ICS_HEXDUMP_QUOTED, "CIP - network segment, ");
            } break;
            case CIP_SEGT_SYMBOLIC: {
                CipSymbolicSegment *symbolicSegment;
                if((r = parseSymbolicSegment(padded, &symbolicSegment, data, octets, &o)) != ICS_RESULT_OK)
                    return r;
                opaque = symbolicSegment;
            } break;
            case CIP_SEGT_DATA: {
                CipDataSegment *dataSegment;
                if((r = parseDataSegment(padded, &dataSegment, data, octets, &o)) != ICS_RESULT_OK)
                    return r;
                opaque = dataSegment;
                icsSaveHex(data, octets, octets, ICS_HEXDUMP_QUOTED, "CIP - data segment, ");
            } break;
            case CIP_SEGT_CTYPE: {
                CipCTypeSegment *ctypeSegment;
                if((r = parseCTypeSegment(padded, &ctypeSegment, data, octets, &o)) != ICS_RESULT_OK)
                    return r;
                opaque = ctypeSegment;
                icsSaveHex(data, octets, octets, ICS_HEXDUMP_QUOTED, "CIP - ctype segment, ");
            } break;
            case CIP_SEGT_ETYPE: {
                CipETypeSegment *etypeSegment;
                if((r = parseETypeSegment(padded, &etypeSegment, data, octets, &o)) != ICS_RESULT_OK)
                    return r;
                opaque = etypeSegment;
                icsSaveHex(data, octets, octets, ICS_HEXDUMP_QUOTED, "CIP - etype segment, ");
            } break;
            default: break;
        }
        if(current == NULL) {
            ICS_TMEMORY_P(newSegment, CipSegment);
            *segmentBase = current = newSegment;
        }
        else {
            ICS_TMEMORY_P(newSegment, CipSegment);
            current = current->next = newSegment;
        }
        current->type = type;
        current->opaque = opaque;
    }
    *po = o;
    return ICS_RESULT_OK;
}

static IcsParseResult parseHeader(CipHeader **header, iecBYTE *data, iecUDINT octets, int *po)
{
    int o = *po;
    ICS_TMEMORY(current, CipHeader);
    *header = current;
    ICS_USINT(current->service);
    if((current->service & CIP_SRV_RESPONSEMASK) != CIP_SRV_RESPONSEMASK) {
        current->isRequest  = iecTRUE;
        current->isResponse = iecFALSE;
    } else {
        current->isRequest  = iecFALSE;
        current->isResponse = iecTRUE;
        current->service &= CIP_SRV_MASK;
    }
    if(avoidFunc(current->service))
        return ICS_RESULT_FUNCTIONIGNORED;
    if(reverseLookupService(current->service) == NULL)
        current->isUnknownService = iecTRUE;
    if(current->service == CIP_SRV_MSP)
        current->isMsp = iecTRUE;
    *po = o;
    icsSaveHex(data, octets, octets, ICS_HEXDUMP_QUOTED, "CIP - well-formed header (rs:%u), ", current->isResponse);
    return ICS_RESULT_OK;
}

static IcsParseResult parsePath(CipSegment **path, iecBYTE *data, iecUDINT octets, int *po)
{
    int r;
    if((r = parseSegments(iecTRUE, path, data, octets, po)) != ICS_RESULT_OK)
        return r;
    return ICS_RESULT_OK;
}

static IcsParseResult parseStatus(CipStatus **status, iecBYTE *data, iecUDINT octets, int *po)
{
    int o = *po;
    ICS_TMEMORY_P(current, CipStatus);
    *status = current;
    ICS_USINT(current->reserved);
    ICS_USINT(current->status);
    ICS_USINT(current->addlLength);
    if(current->addlLength > 0)
        ICS_WORDS(current->addlStatus, current->addlLength);
    *po = o;
    icsSaveHex(data, octets, octets, ICS_HEXDUMP_QUOTED, "CIP - response status (0x%02x), ", current->status);
    return ICS_RESULT_OK;
}

static IcsParseResult parseData(CipData **cipdata, iecBOOL isMsp, iecBYTE *data, iecUDINT octets, int *po)
{
    int o = *po;
    ICS_TMEMORY_P(current, CipData);
    *cipdata = current;
    iecUINT start = o, stop = octets;
    if(isMsp) {
        ICS_UINT(iecUINT mspServiceCount);
        ICS_UINT(start);
        int i;
        for(i=0; i < mspServiceCount - 1; i++) {
            ICS_UINT(stop);
            if((current->length = stop - start) > 0) {
                int o = *po + start;
                ICS_BYTES(current->data, current->length);
            }
            ICS_TMEMORY_P(newData, CipData);
            current = current->next = newData;
            start = stop;
        }
        o = (start += *po);
        stop = octets;
    }
    if((current->length = stop - start) > 0) {
        ICS_BYTES(current->data, current->length);
    }
    *po += stop;
    icsSaveHex(data, octets, octets, ICS_HEXDUMP_QUOTED, "CIP - data, ");
    return ICS_RESULT_OK;
}

static IcsParseResult cipProbe(iecBYTE *data, iecUDINT octets)
{
    int o = 0;
    ICS_BYTE(CipService service);
    if((service & CIP_SRV_RESPONSEMASK) == 0x00) {
        if(reverseLookupService(service) == NULL)
            return ICS_RESULT_UNKNOWNFUNCTION;
        ICS_USINT(iecUSINT pathSize);
        if(octets - o < pathSize * 2)
            return ICS_RESULT_SHORT;
    } else {
        service &= CIP_SRV_MASK;
        if(reverseLookupService(service) == NULL)
            return ICS_RESULT_UNKNOWNFUNCTION;
        ICS_USINT(iecUSINT reserved);
        if(reserved != 0)
            return ICS_RESULT_INVALIDCODING;
    }
    return ICS_RESULT_OK;
}

static IcsParseResult parse(Cip **cip, iecBYTE *data, iecUDINT octets, int *po)
{
    int r, o = *po;
    CipHeader *header;
    if((r = parseHeader(&header, data, octets, &o)) != ICS_RESULT_OK)
        return r;

    ICS_TMEMORY_P(current, Cip);
    *cip = current;
    current->header = header;

    if(!current->header->isUnknownService) {
        if(current->header->isRequest) {
            if((r = parsePath(&(current->rqPath), data, octets, &o)) != ICS_RESULT_OK)
                return r;
            if((r = parseData(&(current->rqData), current->header->isMsp, data, octets, &o)) != ICS_RESULT_OK)
                return r;
            icsSaveHex(data, octets, octets, ICS_HEXDUMP_QUOTED, "CIP - request data, ");
        }
        else
        if(current->header->isResponse) {
            if((r = parseStatus(&(current->rsStatus), data, octets, &o)) != ICS_RESULT_OK)
                return r;
            if((r = parseData(&(current->rsData), current->header->isMsp, data, octets, &o)) != ICS_RESULT_OK)
                return r;
            icsSaveHex(data, octets, octets, ICS_HEXDUMP_QUOTED, "CIP - response data, ");
        }
        else
            r = ICS_RESULT_INVALIDCONTEXT;
    }
    *po = o;
    return r;
}

static IcsTransaction *cipTransaction(IcsStack *stack, iecSINT *outerKey, Cip *cip, int index)
{
    IcsTransaction *transaction = NULL;
    int keyLength = strlen(outerKey) + 16;
    ICS_SMEMORY(transactionKey, iecSINT, keyLength + 1);
    if(transactionKey != NULL) {
        snprintf(transactionKey, keyLength, "%s:%02x:%04x", outerKey, cip->header->service, index);
        transaction = NULL;//icsTransactionGet(stack, ICS_PROTO_CIP, transactionKey);
        if(transaction == NULL)
            if((transaction = icsTransactionNew(stack, ICS_PROTO_CIP, transactionKey, NULL, 30, iecFALSE)) != NULL)
                transaction->opaque = cip;
        ICS_FREE(transactionKey);
    }
    return transaction;
}

static IcsHash *globals;
iecDINT icsInitializeCip(char *(*configLoader)(char *name))
{
    ICS_FETCH_CONFIG_NUMBER(configLoader, "libics.CIP.transactionmax");
    ICS_FETCH_CONFIG_STRING(configLoader, "libics.CIP.avoidfuncs");
    ICS_FETCH_CONFIG_STRING(configLoader, "libics.CIP.servertcpports");
    ICS_FETCH_CONFIG_STRING(configLoader, "libics.CIP.serverudpports");

    iecUINT transMax;
    if((transMax = icsConfigGetNumber("libics.CIP.transactionmax")) != ICS_DEFAULT_MAXTRANS)
        transactionMaxima[ICS_PROTO_CIP] = transMax;

    if(globals == NULL) {
        if((globals = icsHashCreate(256, 90, SCHA_DEFAULT)) != NULL) {
            int i;
            for(i=0; cipServices[i].name; i++)
                icsHashSetItem(globals, cipServices[i].name, icsCreatePredicateValue(SPVT_NUMERIC, cipServices[i].value, NULL));
            for(i=0; cipStatuses[i].name; i++)
                icsHashSetItem(globals, cipStatuses[i].name, icsCreatePredicateValue(SPVT_NUMERIC, cipStatuses[i].value, NULL));
            for(i=0; cipObjectIDs[i].name; i++)
                icsHashSetItem(globals, cipObjectIDs[i].name, icsCreatePredicateValue(SPVT_NUMERIC, cipObjectIDs[i].value, NULL));
            for(i=0; cipSegmentTypes[i].name; i++)
                icsHashSetItem(globals, cipSegmentTypes[i].name, icsCreatePredicateValue(SPVT_NUMERIC, cipSegmentTypes[i].value, NULL));
            for(i=0; cipLogicalSegmentTypes[i].name; i++)
                icsHashSetItem(globals, cipLogicalSegmentTypes[i].name, icsCreatePredicateValue(SPVT_NUMERIC, cipLogicalSegmentTypes[i].value, NULL));
            for(i=0; cipNetworkSegmentTypes[i].name; i++)
                icsHashSetItem(globals, cipNetworkSegmentTypes[i].name, icsCreatePredicateValue(SPVT_NUMERIC, cipNetworkSegmentTypes[i].value, NULL));
            for(i=0; cipDataSegmentTypes[i].name; i++)
                icsHashSetItem(globals, cipDataSegmentTypes[i].name, icsCreatePredicateValue(SPVT_NUMERIC, cipDataSegmentTypes[i].value, NULL));
        }
    }

    if(avoidFuncs == NULL) {
        iecSINT *list = icsConfigGetString("libics.CIP.avoidfuncs");
        if(list != NULL)
            avoidFuncs = icsNumberArrayFromCommaList(list, 0, &avoidFuncCount);
    }

    return globals == NULL ? 0 : 1;
}

void icsUninitializeCip(void)
{
    if(globals != NULL)
        icsFreePredicateHash(globals);
    if(avoidFuncs != NULL)
        ICS_FREE(avoidFuncs);
}

IcsDetectItem *icsMungeCip(const char *keyword, const char *options)
{
    ICS_TMEMORY(item, IcsDetectItem);
    item->predicate = NULL;
    item->globals   = globals;
    item->constants = icsHashCreate(64, 90, SCHA_DEFAULT);
    item->protocol  = ICS_PROTO_CIP;

    if(keyword == NULL || strcmp(keyword, "cip") == 0)
        item->predicate = icsStrdup(options);
    else
    if(strcmp(keyword, "cip_func") == 0) {
        IcsPredicateValue *funcs = icsNumberArrayFromKeywordParameters(options, cipServices);
        if(funcs != NULL) {
            icsHashSetItem(item->constants, "sig.services", funcs);
            item->predicate = icsStrdup(CIP_PREDICATE_FUNCTION);
        }
    }
    else
    if(strcmp(keyword, "cip_obj") == 0) {
        IcsPredicateValue *objspec = icsNumberArrayFromKeywordParameters(options, cipObjectIDs);
        if(objspec != NULL) {
            iecSINT *predicate = NULL;
            if(objspec->count > 0) {
                icsHashSetItem(item->constants, "sig.classid", icsGetPredicateArrayItem(objspec, 0));
                predicate = CIP_PREDICATE_CLASSID;
            }
            if(objspec->count == 2) {
                icsHashSetItem(item->constants, "sig.attrid", icsGetPredicateArrayItem(objspec, 1));
                predicate = CIP_PREDICATE_CLASSID " && "
                            CIP_PREDICATE_ATTRID;
            }
            else
            if(objspec->count > 2) {
                icsHashSetItem(item->constants, "sig.instid", icsGetPredicateArrayItem(objspec, 1));
                icsHashSetItem(item->constants, "sig.attrid", icsGetPredicateArrayItem(objspec, 2));
                predicate = CIP_PREDICATE_CLASSID " && "
                            CIP_PREDICATE_INSTID  " && "
                            CIP_PREDICATE_ATTRID;
            }
            if(predicate != NULL)
                item->predicate = icsStrdup(predicate);
        }
        icsFreePredicateValue(&objspec);
    }
    else
    if(strcmp(keyword, "cip_stat") == 0) {
        IcsPredicateValue *stats = icsNumberArrayFromKeywordParameters(options, cipStatuses);
        if(stats != NULL) {
            icsHashSetItem(item->constants, "sig.statuses", stats);
            item->predicate = icsStrdup(CIP_PREDICATE_STATUS);
        }
    }
    return item;
}

void icsFreeCip(IcsOpaque *p)
{
    Cip *cip = p;
    if(cip != NULL) {
        if(cip->header != NULL)
            ICS_FREE(cip->header);
        CipSegment *segment = cip->rqPath;
        while(segment != NULL) {
            CipSegment *next = segment->next;
            freeSegment(segment->type, segment->opaque);
            ICS_FREE(segment);
            segment = next;
        }
        CipData *data = cip->rqData;
        while(data != NULL) {
            CipData *next = data->next;
            ICS_FREE(data->data);
            ICS_FREE(data);
            data = next;
        }
        if(cip->rsStatus != NULL) {
            ICS_FREE(cip->rsStatus->addlStatus);
            ICS_FREE(cip->rsStatus);
        }
        data = cip->rsData;
        while(data != NULL) {
            CipData *next = data->next;
            ICS_FREE(data->data);
            ICS_FREE(data);
            data = next;
        }
        ICS_FREE(cip);
    }
}

IcsParseResult icsParseCip(IcsLayer startLayer, IcsMode mode, iecBYTE *data, iecUDINT octets, IcsStack *stack)
{
    ICS_IGNORE(mode);
    if((startLayer & ICS_LAYER_APPLICATION) != ICS_LAYER_APPLICATION)
        return ICS_RESULT_UNSUPPORTEDLAYER;
    if((startLayer & ICS_LAYER_ENCAP) != ICS_LAYER_ENCAP)
        return ICS_RESULT_ENCAPREQUIRED;
    IcsProtocol encapsulatingProtocol = (startLayer & ICS_LAYER_PROTOMASK);
    iecSINT *outerKey = stack->application.outerKeys[encapsulatingProtocol];
    if(outerKey == NULL)
        outerKey = "none";

    int r, o = 0;

    Cip *cip = NULL;
    if((r = parse(&cip, data, octets, &o)) != ICS_RESULT_OK)
        return r;

    IcsTransaction *transaction = NULL;
    if(cip->header->isMsp) {
        icsSaveHex(data, octets, octets, ICS_HEXDUMP_QUOTED, "CIP - multiple service packet (rs:%u), ", cip->header->isResponse);
        CipData *item = cip->header->isRequest ? cip->rqData : cip->rsData;
        int index = 0;
        while(item != NULL) {
            int o = 0;
            Cip *cip = NULL;
            if((r = parse(&cip, item->data, item->length, &o)) != ICS_RESULT_OK)
                break;
            if((transaction = cipTransaction(stack, outerKey, cip, index)) != NULL)
                shoveVariables(transaction);
            if(cip->header->isResponse)
                icsTransactionMarkComplete(transaction);
            item = item->next;
            index++;
        }
    }
    else {
        icsSaveHex(data, octets, octets, ICS_HEXDUMP_QUOTED, "CIP - single item (rs:%u), ", cip->header->isResponse);
        if((transaction = cipTransaction(stack, outerKey, cip, 0)) != NULL)
            shoveVariables(transaction);
        icsTransactionMarkComplete(transaction);
    }

    return r;
}

IcsProtocol icsProbeCip(IcsLayer startLayer, iecBYTE *data, iecUDINT octets)
{
    if((startLayer & ICS_LAYER_APPLICATION) != ICS_LAYER_APPLICATION ||
       (startLayer & ICS_LAYER_ENCAP) != ICS_LAYER_ENCAP)
        return ICS_PROTO_NONE;

    if(cipProbe(data, octets) != ICS_RESULT_OK)
        return ICS_PROTO_NONE;
    return ICS_PROTO_CIP;
}
