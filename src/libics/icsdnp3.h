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

#if !defined(_icsdnp3_h)
#define _icsdnp3_h

#include "ics.h"
#include "icspredicate.h"

#define DNP3_HDR_LEN        0x0a
#define DNP3_MAX_CHUNK_SIZE 0x10
#define DNP3_SIGNATURE      0x0564
#define DNP3_MAX_FUNCTION   0x7f

#define DNP3_PREDICATE_FALSE            "0"
#define DNP3_PREDICATE_TRUE             "1"
#define DNP3_PREDICATE_FUNCTION         "dnp3.application.function in sig.functions"
#define DNP3_PREDICATE_SOURCE           "dnp3.datalink.source in sig.sources"
#define DNP3_PREDICATE_DESTINATION      "dnp3.datalink.destination in sig.destinations"
#define DNP3_PREDICATE_INDICATION       "(dnp3.application.indication & sig.indications) != 0x0000"
#define DNP3_PREDICATE_OBJECTTYPE       "dnp3.application.object.type == sig.objtype"
#define DNP3_PREDICATE_OBJECTINDEX      "dnp3.application.object.index == sig.objindex"
#define DNP3_PREDICATE_OBJECTQUALIFIER  "dnp3.application.object.qualifier == sig.objqualifier"
#define DNP3_PREDICATE_ERRORBADDLCRC    "dnp3.datalink.hasInvalidChecksum == 1"
#define DNP3_PREDICATE_ERRORBADTLCRC    "dnp3.transport.hasInvalidChecksum == 1"
#define DNP3_PREDICATE_ERRORBADALFUNC   "dnp3.application.hasInvalidFunction == 1"

typedef enum tagDnp3DLExempt {
    DNP3_DLFCN_FRL             = 0x00,
    DNP3_DLFCN_FLS             = 0x09,
    DNP3_DLFCN_FSL             = 0x0b
} Dnp3DLExempt;

typedef enum tagDnp3DLControl {
    DNP3_DLCTL_PARAMETERMASK   = 0xf0,
    DNP3_DLCTL_DIRECTION       = 0x80,
    DNP3_DLCTL_PRIMARY         = 0x40,
    DNP3_DLCTL_FRAMECOUNTBIT   = 0x20,
    DNP3_DLCTL_FRAMECOUNTVALID = 0x10,
    DNP3_DLCTL_FUNCTIONMASK    = 0x0f
} Dnp3DLControl;

typedef enum tagDnp3TLControl {
    DNP3_TLCTL_FINAL           = 0x80,
    DNP3_TLCTL_FIRST           = 0x40,
    DNP3_TLCTL_SEQUENCEMASK    = 0x3f
} Dnp3TLControl;

typedef enum tagDnp3ALControl {
    DNP3_ALCTL_FIRST           = 0x80,
    DNP3_ALCTL_FINAL           = 0x40,
    DNP3_ALCTL_CONFIRM         = 0x20,
    DNP3_ALCTL_UNSOLICITED     = 0x10,
    DNP3_ALCTL_SEQUENCEMASK    = 0x0f
} Dnp3ALControl;

typedef struct tagDnp3DataLinkLayer {
    iecUINT  signature;
    iecUSINT length;
    iecUSINT control;
    iecUINT  destination;
    iecUINT  source;
    iecUINT  crc;
    iecBOOL  hasInvalidChecksum;
    iecUSINT controlFunction;
    iecUSINT controlParameter;
    iecBOOL  hasUnparsedControlFunctions;
    iecBOOL  isResponse;
} Dnp3DataLinkLayer;

typedef struct tagDnp3TLFragment {
    iecUINT  length;
    iecUSINT *data;
    struct tagDnp3TLFragment *next;
} Dnp3TLFragment;

typedef struct tagDnp3TransportLayer {
    iecUSINT       control;
    iecUINT        sequence;
    iecBOOL        hasSequenceError;
    iecBOOL        hasFirstFragment;
    iecBOOL        hasMiddleFragment;
    iecBOOL        hasLastFragment;
    Dnp3TLFragment *fragment;
    iecBOOL        hasInvalidChecksum;
    // don't free data
    iecBYTE  *data;
    iecUDINT octets;
    iecUDINT o;
} Dnp3TransportLayer;

typedef struct tagDnp3ApplicationLayer {
    iecUSINT control;
    iecUSINT function;
    iecUINT  indication;
    iecBOOL  hasInvalidFunction;
    iecBOOL  confirm;
    iecBOOL  unsolicited;
    struct {
        iecUSINT type;
        iecUSINT index;
        iecUSINT qualifier;
    } object;
} Dnp3ApplicationLayer;

typedef struct tagDnp3 {
    Dnp3DataLinkLayer    *dataLinkLayer;
    Dnp3TransportLayer   *transportLayer;
    Dnp3ApplicationLayer *applicationLayer;
} Dnp3;

iecDINT          icsInitializeDnp3(char *(*configLoader)(char *name));
void             icsUninitializeDnp3(void);
void             icsFreeDnp3(IcsOpaque *p);

IcsParseResult icsParseDnp3(IcsLayer startLayer, IcsMode mode,
                                iecBYTE *data, iecUDINT octets,
                                IcsStack *stack);

IcsProtocol    icsProbeDnp3(IcsLayer startLayer,
                                iecBYTE *data, iecUDINT octets);

IcsDetectItem *icsMungeDnp3(const iecSINT *keyword, const iecSINT *options);

IcsHash       *icsNamesDnp3(void);

#endif
