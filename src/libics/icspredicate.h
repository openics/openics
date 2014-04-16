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
 * Predicate parser for sophisticated rule crunching.
 *
 */

#if !defined(_icspredicate_h)
#define _icspredicate_h

#include "ics.h"

#define ICS_SHOVENUMBER(label, field) {                                 \
    IcsPredicateValue *v = icsCreatePredicateNumber(field);             \
    icsHashSetItem(transaction->variables, label, v);                       \
}

#define ICS_SHOVESTRING(label, field) {                                 \
    IcsPredicateValue *v = icsCreatePredicateString(field);             \
    icsHashSetItem(transaction->variables, label, v);                       \
}

#define ICS_SHOVEDATA(label, field, size, length)

#define ICS_SHOVEARRAY(label, base, field, link) {                      \
    IcsPredicateValue *a = icsCreatePredicateArray();                   \
    IcsOpaque *b = base;                                                    \
    while(base != NULL) {                                                   \
        IcsPredicateValue *v = icsCreatePredicateNumber(base->field);   \
        icsAppendPredicateValue(a, v);                                  \
        base = base->link;                                                  \
    }                                                                       \
    base = b;                                                               \
    icsHashSetItem(transaction->variables, label, a);                       \
}

typedef enum tagIcsPredicateValueType {
    SPVT_NONE,
    SPVT_NUMERIC,
    SPVT_STRING,
    SPVT_ARRAY
} IcsPredicateValueType;

typedef enum tagIcsPredicateTokenType {
    SPTT_NONE,
    SPTT_NAME,
    SPTT_NUMBER,
    SPTT_STRING,
    SPTT_END,
    SPTT_BITSHL,
    SPTT_BITSHR,
    SPTT_BITINV = '~',
    SPTT_CAT = '.',
    SPTT_PLUS = '+',
    SPTT_MINUS = '-',
    SPTT_MULTIPLY = '*',
    SPTT_DIVIDE = '/',
    SPTT_ASSIGN = '=',
    SPTT_LHPAREN = '(',
    SPTT_RHPAREN = ')',
    SPTT_LBRACKET = '[',
    SPTT_RBRACKET = ']',
    SPTT_COMMA = ',',
    SPTT_NOT = '!',
    SPTT_BITAND = '&',
    SPTT_BITOR = '|',
    SPTT_BITXOR = '^',

    // comparisons
    SPTT_LT = '<',
    SPTT_GT = '>',
    SPTT_LE,
    SPTT_GE,
    SPTT_EQ,
    SPTT_NE,
    SPTT_AND,
    SPTT_OR,
    SPTT_IN,

    // special assignments
    SPTT_ASSIGN_ADD,
    SPTT_ASSIGN_CAT,
    SPTT_ASSIGN_SUB,
    SPTT_ASSIGN_MUL,
    SPTT_ASSIGN_DIV
} IcsPredicateTokenType;

typedef struct tagIcsPredicateValue {
    IcsPredicateValueType type;
    iecLREAL d;
    iecSINT  *s;
    iecUINT  count;
    struct tagIcsPredicateValue *next;
} IcsPredicateValue;

typedef struct tagIcsPredicateParseContext {
    IcsPredicateTokenType type;
    IcsPredicateValue     *value;
    iecSINT *token;
    iecSINT *predicate;
    iecSINT *pointer;
    IcsHash *globals;
    IcsHash *constants;
    IcsHash *variables;
    IcsHash *locals;
    IcsFifo *output;
} IcsPredicateParseContext;

IcsFifo           *icsPredicateEvaluate(iecSINT *predicate,
                                        IcsHash *globals,
                                        IcsHash *constants,
                                        IcsHash *variables);

IcsPredicateValue *icsCreatePredicateValue(IcsPredicateValueType type, iecLREAL d, const iecSINT *s);
IcsPredicateValue *icsCreatePredicateString(const iecSINT *s);
IcsPredicateValue *icsCreatePredicateNumber(iecLREAL d);
IcsPredicateValue *icsCreatePredicateArray(void);
IcsPredicateValue *icsEmptyPredicateArray(IcsPredicateValue *array);
IcsPredicateValue *icsAppendPredicateValue(IcsPredicateValue *array, IcsPredicateValue *value);
void               icsFreePredicateValue(IcsPredicateValue **pv);
void               icsFreePredicateHash(IcsHash *h);

IcsPredicateValue *icsNumberArrayFromKeywordParameters(const iecSINT *parameters, IcsNumericAssociation *table);
IcsPredicateValue *icsStringArrayFromKeywordParameters(const iecSINT *parameters);
IcsPredicateValue *icsBitfieldFromKeywordParameters(const iecSINT *parameters, IcsNumericAssociation *table);
IcsPredicateValue *icsGetPredicateArrayItem(IcsPredicateValue *array, iecUINT index);
IcsPredicateValue *icsFindPredicateArrayNumberItem(IcsPredicateValue *array, iecLREAL d);
IcsPredicateValue *icsFindPredicateArrayStringItem(IcsPredicateValue *array, const iecSINT *s);

#endif
