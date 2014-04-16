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

#include "icspredicate.h"

static IcsPredicateParseContext *createParseContext(iecSINT *predicate, IcsHash *globals, IcsHash *constants, IcsHash *variables);
static void freeParseContext(IcsPredicateParseContext *context);

static iecSINT *extractQuotedString(iecSINT **source);
static IcsPredicateTokenType getToken(IcsPredicateParseContext *context, iecBOOL ignoreSign);
static IcsPredicateValue *primary(IcsPredicateParseContext *context);
static IcsPredicateValue *term(IcsPredicateParseContext *context);
static IcsPredicateValue *addSubtract(IcsPredicateParseContext *context);
static IcsPredicateValue *comparison(IcsPredicateParseContext *context);
static IcsPredicateValue *expression(IcsPredicateParseContext *context);
static IcsPredicateValue *array(IcsPredicateParseContext *context);
static IcsPredicateValue *commaList(IcsPredicateParseContext *context);
static IcsPredicateValue *evaluate(IcsPredicateParseContext *context);
static IcsPredicateValue *newValue(IcsPredicateValueType type, iecLREAL d, const iecSINT *s);
static IcsPredicateValue *newValue1(IcsPredicateValueType type, iecLREAL d, const iecSINT *s);
static IcsPredicateValue *newValue2(IcsPredicateValueType type, iecLREAL d, const iecSINT *s);
static IcsPredicateValue *newValue3(IcsPredicateValueType type, iecLREAL d, const iecSINT *s);
static IcsPredicateValue *newValue4(IcsPredicateValueType type, iecLREAL d, const iecSINT *s);
static IcsPredicateValue *dupeValue(IcsPredicateValue *v);
static IcsPredicateValue *getSymbol(IcsPredicateParseContext *context, const iecSINT *name);
static IcsPredicateValue *invValue(IcsPredicateValue *dv);
static IcsPredicateValue *negValue(IcsPredicateValue *dv);
static IcsPredicateValue *bivValue(IcsPredicateValue *dv);
static iecBOOL checkToken(IcsPredicateParseContext *context, IcsPredicateTokenType wanted);
static void setSymbol(IcsPredicateParseContext *context, const iecSINT *name, IcsPredicateValue *v);
static void coerceValue(IcsPredicateValue *v, IcsPredicateValueType type);
static void addValue(IcsPredicateValue *dv, IcsPredicateValue *sv);
static void ainValue(IcsPredicateValue *dv, IcsPredicateValue *sv);
static void andValue(IcsPredicateValue *dv, IcsPredicateValue *sv);
static void beqValue(IcsPredicateValue *dv, IcsPredicateValue *sv);
static void bgeValue(IcsPredicateValue *dv, IcsPredicateValue *sv);
static void bgtValue(IcsPredicateValue *dv, IcsPredicateValue *sv);
static void bleValue(IcsPredicateValue *dv, IcsPredicateValue *sv);
static void bltValue(IcsPredicateValue *dv, IcsPredicateValue *sv);
static void bneValue(IcsPredicateValue *dv, IcsPredicateValue *sv);
static void catValue(IcsPredicateValue *dv, IcsPredicateValue *sv);
static void divValue(IcsPredicateValue *dv, IcsPredicateValue *sv);
static void mulValue(IcsPredicateValue *dv, IcsPredicateValue *sv);
static void rorValue(IcsPredicateValue *dv, IcsPredicateValue *sv);
static void banValue(IcsPredicateValue *dv, IcsPredicateValue *sv);
static void borValue(IcsPredicateValue *dv, IcsPredicateValue *sv);
static void bxrValue(IcsPredicateValue *dv, IcsPredicateValue *sv);
static void shlValue(IcsPredicateValue *dv, IcsPredicateValue *sv);
static void shrValue(IcsPredicateValue *dv, IcsPredicateValue *sv);
static void setValue(IcsPredicateValue *dv, IcsPredicateValue *sv);
static void subValue(IcsPredicateValue *dv, IcsPredicateValue *sv);

static IcsPredicateValue *invValue(IcsPredicateValue *dv)
{
    if(dv->type == SPVT_NONE)
        return dv;
    if(dv->type == SPVT_STRING)
        coerceValue(dv, SPVT_NUMERIC);
    dv->d = (dv->d == 0.0 ? 1.0 : 0.0);
    return dv;
}

static IcsPredicateValue *negValue(IcsPredicateValue *dv)
{
    if(dv->type == SPVT_NONE)
        return dv;
    if(dv->type == SPVT_STRING)
        coerceValue(dv, SPVT_NUMERIC);
    dv->d = -(dv->d);
    return dv;
}

static IcsPredicateValue *bivValue(IcsPredicateValue *dv)
{
    if(dv->type == SPVT_NONE)
        return dv;
    if(dv->type == SPVT_STRING)
        coerceValue(dv, SPVT_NUMERIC);
    dv->d = (iecLREAL) ~((iecUDINT) dv->d);
    return dv;
}

static void coerceValue(IcsPredicateValue *v, IcsPredicateValueType type)
{
    if(type == SPVT_NONE) {
        if(v->type == SPVT_ARRAY)
            icsFreePredicateValue(&(v->next));
        v->type = SPVT_NONE;
        v->d = 0.0;
        ICS_FREE(v->s);
        return;
    }
    if(v->type == SPVT_NONE) {
        v->type = SPVT_NUMERIC;
        v->d = 0.0;
        ICS_FREE(v->s);
    }
    if(v->type == type)
        return;
    if(type == SPVT_NUMERIC) {
        if(v->type == SPVT_ARRAY) {
            iecUINT u = v->count;
            icsFreePredicateValue(&(v->next));
            v->next = NULL;
            v->d = u;
            v->count = 0;
        } else {
            if(v->s == NULL || *(v->s) == '\0')
                v->d = 0.0;
            else
                v->d = strtod(v->s, NULL);
            ICS_FREE(v->s);
        }
    }
    else
    if(type == SPVT_STRING) {
        if(v->type == SPVT_ARRAY) {
            iecUINT u = v->count;
            icsFreePredicateValue(&(v->next));
            v->next = NULL;
            v->d = u;
            v->count = 0;
        }
        ICS_SMEMORY(newS, iecSINT, 64);
        v->s = newS;
        if(fmod(v->d, 1.0) > 0.0)
            snprintf(v->s, 64, "%.4f", v->d);
        else
            snprintf(v->s, 64, "%ld", (long) v->d);
    }
    else
    if(type == SPVT_ARRAY) {
        ICS_TMEMORY(newV, IcsPredicateValue);
        newV->type = v->type;
        if(v->type == SPVT_STRING)
            newV->s = v->s;
        else
        if(v->type == SPVT_NUMERIC)
            newV->d = v->d;
        v->next = newV;
        v->d = 0;
        v->s = NULL;
        v->count = 1;
    }
    v->type = type;
}

static void catValue(IcsPredicateValue *dv, IcsPredicateValue *sv)
{
    if(dv->type != SPVT_STRING)
        coerceValue(dv, SPVT_STRING);
    if(sv->type != SPVT_STRING)
        coerceValue(sv, SPVT_STRING);
    int l = strlen(dv->s) + strlen(sv->s) + 1;
    ICS_SMEMORY(s, iecSINT, l);
    snprintf(s, l, "%s%s", dv->s, sv->s);
    ICS_FREE(dv->s);
    dv->s = s;
    icsFreePredicateValue(&sv);
}

static void addValue(IcsPredicateValue *dv, IcsPredicateValue *sv)
{
    if(dv->type != SPVT_NUMERIC)
        coerceValue(dv, SPVT_NUMERIC);
    if(sv->type != SPVT_NUMERIC)
        coerceValue(sv, SPVT_NUMERIC);
    dv->d += sv->d;
    icsFreePredicateValue(&sv);
}

static void ainValue(IcsPredicateValue *dv, IcsPredicateValue *sv)
{
    if(dv->type != SPVT_ARRAY)
        coerceValue(dv, SPVT_ARRAY);
    if(sv->type != SPVT_ARRAY)
        coerceValue(sv, SPVT_ARRAY);
    IcsPredicateValue *new = icsCreatePredicateArray();
    IcsPredicateValue *sitem = sv->next;
    while(sitem != NULL) {
        IcsPredicateValue *ditem = dv->next;
        while(ditem != NULL) {
            if(ditem->d == sitem->d) {
                icsAppendPredicateValue(new, newValue(sitem->type, sitem->d, sitem->s));
                break;
            }
            ditem = ditem->next;
        }
        sitem = sitem->next;
    }
    setValue(dv, new);
    icsFreePredicateValue(&sv);
}

static void andValue(IcsPredicateValue *dv, IcsPredicateValue *sv)
{
    if(dv->type != SPVT_NUMERIC)
        coerceValue(dv, SPVT_NUMERIC);
    if(sv->type != SPVT_NUMERIC)
        coerceValue(sv, SPVT_NUMERIC);
    dv->d = (dv->d > 0.0 && sv->d > 0.0 ? 1.0 : 0.0);
    icsFreePredicateValue(&sv);
}

static void beqValue(IcsPredicateValue *dv, IcsPredicateValue *sv)
{
    if(dv->type != SPVT_NUMERIC)
        coerceValue(dv, SPVT_NUMERIC);
    if(sv->type != SPVT_NUMERIC)
        coerceValue(sv, SPVT_NUMERIC);
    dv->d = (dv->d == sv->d ? 1.0 : 0.0);
    icsFreePredicateValue(&sv);
}

static void bgeValue(IcsPredicateValue *dv, IcsPredicateValue *sv)
{
    if(dv->type != SPVT_NUMERIC)
        coerceValue(dv, SPVT_NUMERIC);
    if(sv->type != SPVT_NUMERIC)
        coerceValue(sv, SPVT_NUMERIC);
    dv->d = (dv->d >= sv->d ? 1.0 : 0.0);
    icsFreePredicateValue(&sv);
}

static void bgtValue(IcsPredicateValue *dv, IcsPredicateValue *sv)
{
    if(dv->type != SPVT_NUMERIC)
        coerceValue(dv, SPVT_NUMERIC);
    if(sv->type != SPVT_NUMERIC)
        coerceValue(sv, SPVT_NUMERIC);
    dv->d = (dv->d > sv->d ? 1.0 : 0.0);
    icsFreePredicateValue(&sv);
}

static void bleValue(IcsPredicateValue *dv, IcsPredicateValue *sv)
{
    if(dv->type != SPVT_NUMERIC)
        coerceValue(dv, SPVT_NUMERIC);
    if(sv->type != SPVT_NUMERIC)
        coerceValue(sv, SPVT_NUMERIC);
    dv->d = (dv->d <= sv->d ? 1.0 : 0.0);
    icsFreePredicateValue(&sv);
}

static void bltValue(IcsPredicateValue *dv, IcsPredicateValue *sv)
{
    if(dv->type != SPVT_NUMERIC)
        coerceValue(dv, SPVT_NUMERIC);
    if(sv->type != SPVT_NUMERIC)
        coerceValue(sv, SPVT_NUMERIC);
    dv->d = (dv->d < sv->d ? 1.0 : 0.0);
    icsFreePredicateValue(&sv);
}

static void bneValue(IcsPredicateValue *dv, IcsPredicateValue *sv)
{
    if(dv->type != SPVT_NUMERIC)
        coerceValue(dv, SPVT_NUMERIC);
    if(sv->type != SPVT_NUMERIC)
        coerceValue(sv, SPVT_NUMERIC);
    dv->d = (dv->d != sv->d ? 1.0 : 0.0);
    icsFreePredicateValue(&sv);
}

static void divValue(IcsPredicateValue *dv, IcsPredicateValue *sv)
{
    if(dv->type != SPVT_NUMERIC)
        coerceValue(dv, SPVT_NUMERIC);
    if(sv->type != SPVT_NUMERIC)
        coerceValue(sv, SPVT_NUMERIC);
    if(sv->d != 0.0)
        dv->d /= sv->d;
    icsFreePredicateValue(&sv);
}

static void mulValue(IcsPredicateValue *dv, IcsPredicateValue *sv)
{
    if(dv->type != SPVT_NUMERIC)
        coerceValue(dv, SPVT_NUMERIC);
    if(sv->type != SPVT_NUMERIC)
        coerceValue(sv, SPVT_NUMERIC);
    dv->d *= sv->d;
    icsFreePredicateValue(&sv);
}

static void rorValue(IcsPredicateValue *dv, IcsPredicateValue *sv)
{
    if(dv->type != SPVT_NUMERIC)
        coerceValue(dv, SPVT_NUMERIC);
    if(sv->type != SPVT_NUMERIC)
        coerceValue(sv, SPVT_NUMERIC);
    dv->d = (dv->d > 0.0 || sv->d > 0.0 ? 1.0 : 0.0);
    icsFreePredicateValue(&sv);
}

static void banValue(IcsPredicateValue *dv, IcsPredicateValue *sv)
{
    if(dv->type != SPVT_NUMERIC)
        coerceValue(dv, SPVT_NUMERIC);
    if(sv->type != SPVT_NUMERIC)
        coerceValue(sv, SPVT_NUMERIC);
    dv->d = (iecLREAL) ((iecUDINT) dv->d & (iecUDINT) sv->d);
    icsFreePredicateValue(&sv);
}

static void borValue(IcsPredicateValue *dv, IcsPredicateValue *sv)
{
    if(dv->type != SPVT_NUMERIC)
        coerceValue(dv, SPVT_NUMERIC);
    if(sv->type != SPVT_NUMERIC)
        coerceValue(sv, SPVT_NUMERIC);
    dv->d = (iecLREAL) ((iecUDINT) dv->d | (iecUDINT) sv->d);
    icsFreePredicateValue(&sv);
}

static void bxrValue(IcsPredicateValue *dv, IcsPredicateValue *sv)
{
    if(dv->type != SPVT_NUMERIC)
        coerceValue(dv, SPVT_NUMERIC);
    if(sv->type != SPVT_NUMERIC)
        coerceValue(sv, SPVT_NUMERIC);
    dv->d = (iecLREAL) ((iecUDINT) dv->d ^ (iecUDINT) sv->d);
    icsFreePredicateValue(&sv);
}

static void shlValue(IcsPredicateValue *dv, IcsPredicateValue *sv)
{
    if(dv->type != SPVT_NUMERIC)
        coerceValue(dv, SPVT_NUMERIC);
    if(sv->type != SPVT_NUMERIC)
        coerceValue(sv, SPVT_NUMERIC);
    dv->d = (iecLREAL) ((iecUDINT) dv->d << (iecUDINT) sv->d);
    icsFreePredicateValue(&sv);
}

static void shrValue(IcsPredicateValue *dv, IcsPredicateValue *sv)
{
    if(dv->type != SPVT_NUMERIC)
        coerceValue(dv, SPVT_NUMERIC);
    if(sv->type != SPVT_NUMERIC)
        coerceValue(sv, SPVT_NUMERIC);
    dv->d = (iecLREAL) ((iecUDINT) dv->d >> (iecUDINT) sv->d);
    icsFreePredicateValue(&sv);
}

static void setValue(IcsPredicateValue *dv, IcsPredicateValue *sv)
{
    if(dv->type == SPVT_ARRAY) {
        icsFreePredicateValue(&(dv->next));
        memcpy(dv, sv, sizeof(IcsPredicateValue));
    }
    dv->type = sv->type;
    dv->d = sv->d;
    ICS_FREE(dv->s);
    dv->s = (sv->s == NULL ? NULL : icsStrdup(sv->s));
    dv->next = NULL;
    IcsPredicateValue *svn = sv;
    while((svn = svn->next) != NULL) {
        ICS_TMEMORY(newV, IcsPredicateValue);
        if(newV == NULL)
            break;
        dv = dv->next = newV;
        dv->type = svn->type;
        dv->d = svn->d;
        dv->s = (svn->s == NULL ? NULL : icsStrdup(sv->s));
    }
    icsFreePredicateValue(&sv);
}

static void subValue(IcsPredicateValue *dv, IcsPredicateValue *sv)
{
    if(dv->type != SPVT_NUMERIC)
        coerceValue(dv, SPVT_NUMERIC);
    if(sv->type != SPVT_NUMERIC)
        coerceValue(sv, SPVT_NUMERIC);
    dv->d -= sv->d;
    icsFreePredicateValue(&sv);
}

static iecSINT *extractQuotedString(iecSINT **source)
{
    iecSINT *s = *source;
    if(*s++ != '\'')
        return NULL;
    while(*s && *s != '\'') {
        if(*s == '\\' && *(s+1) == '\'')
            s++;
        s++;
    }
    if(*s++ != '\'')
        return NULL;
    int l = s - *source;
    s = *source;
    *source += l;
    ICS_SMEMORY(ns, iecSINT, l);
    if(ns == NULL)
        return NULL;
    int i, j;
    for(i=1, j=0; i < l-1; i++)
        if(s[i] != '\\')
            ns[j++] = s[i];
    ns[j] = '\0';
    return ns;
}

static iecBOOL checkToken(IcsPredicateParseContext *context, IcsPredicateTokenType wanted)
{
    return context->type == wanted;
}

static IcsPredicateValue *dupeValue(IcsPredicateValue *v)
{
    if(v == NULL)
        return NULL;
    IcsPredicateValue *n = newValue1(v->type, v->d, v->s);
    if(n != NULL && n->type == SPVT_ARRAY) {
        IcsPredicateValue *nv = v->next;
        IcsPredicateValue *nn = n;
        while(nv != NULL) {
            if((nn->next = newValue1(nv->type, nv->d, nv->s)) == NULL)
                break;
            n->count++;
            nv = nv->next;
            nn = nn->next;
        }
    }
    return n;
}

static IcsPredicateValue *newValue(IcsPredicateValueType type, iecLREAL d, const iecSINT *s)
{
    ICS_TMEMORY(v, IcsPredicateValue);
    if(v == NULL)
        return NULL;
    v->type = type;
    v->d = (type == SPVT_NUMERIC ? d : 0.0);
    v->s = (type == SPVT_STRING  ? icsStrdup(s) : NULL);
    v->count = 0;
    return v;
}

static IcsPredicateValue *newValue1(IcsPredicateValueType type, iecLREAL d, const iecSINT *s)
{
    ICS_TMEMORY(v, IcsPredicateValue);
    if(v == NULL)
        return NULL;
    v->type = type;
    v->d = (type == SPVT_NUMERIC ? d : 0.0);
    v->s = (type == SPVT_STRING  ? icsStrdup(s) : NULL);
    v->count = 0;
    return v;
}
static IcsPredicateValue *newValue2(IcsPredicateValueType type, iecLREAL d, const iecSINT *s)
{
    ICS_TMEMORY(v, IcsPredicateValue);
    if(v == NULL)
        return NULL;
    v->type = type;
    v->d = (type == SPVT_NUMERIC ? d : 0.0);
    v->s = (type == SPVT_STRING  ? icsStrdup(s) : NULL);
    v->count = 0;
    return v;
}
static IcsPredicateValue *newValue3(IcsPredicateValueType type, iecLREAL d, const iecSINT *s)
{
    ICS_TMEMORY(v, IcsPredicateValue);
    if(v == NULL)
        return NULL;
    v->type = type;
    v->d = (type == SPVT_NUMERIC ? d : 0.0);
    v->s = (type == SPVT_STRING  ? icsStrdup(s) : NULL);
    v->count = 0;
    return v;
}
static IcsPredicateValue *newValue4(IcsPredicateValueType type, iecLREAL d, const iecSINT *s)
{
    ICS_TMEMORY(v, IcsPredicateValue);
    if(v == NULL)
        return NULL;
    v->type = type;
    v->d = (type == SPVT_NUMERIC ? d : 0.0);
    v->s = (type == SPVT_STRING  ? icsStrdup(s) : NULL);
    v->count = 0;
    return v;
}

static IcsPredicateValue *getSymbol(IcsPredicateParseContext *context, const iecSINT *name)
{
    IcsPredicateValue *v = NULL;
    if(context->locals != NULL)
        v = icsHashGetItem(context->locals, name);
    if(v == NULL && context->variables != NULL)
        v = icsHashGetItem(context->variables, name);
    if(v == NULL && context->constants != NULL)
        v = icsHashGetItem(context->constants, name);
    if(v == NULL && context->globals != NULL)
        v = icsHashGetItem(context->globals, name);
    if(v == NULL)
        return newValue2(SPVT_NONE, 0.0, NULL);
    return dupeValue(v);
}

static void setSymbol(IcsPredicateParseContext *context, const iecSINT *name, IcsPredicateValue *v)
{
    IcsPredicateValue *ve = icsHashGetItem(context->locals, name);
    if(ve != v) {
        icsFreePredicateValue(&ve);
        icsHashSetItem(context->locals, name, v);
    }
}

static IcsPredicateTokenType getToken(IcsPredicateParseContext *context, iecBOOL ignoreSign)
{
    ICS_FREE(context->token);

    if(context->value != NULL)
        icsFreePredicateValue(&(context->value));

    while(*(context->pointer) && isspace(*(context->pointer)))
        (context->pointer)++;

    iecSINT *anchor = context->pointer;

    if(*(context->pointer) == '\0' && context->type == SPTT_END)
        return context->type; // Unexpected end of expression

    iecUSINT c1 = *(context->pointer);
    if(c1 == '\0')
        return context->type = SPTT_END;

    iecUSINT c2  = *(context->pointer + 1);

    if(c1 == 'i' && c2 == 'n') {
        if(isspace(*(context->pointer + 2))) {
            context->pointer += 2;
            context->token = icsStrndup(anchor, context->pointer - anchor);
            return context->type = SPTT_IN;
        }
    }

    if(c1 == '0' && (c2 == 'x' || c2 == 'X')) {
        context->pointer += 2;
        while(isxdigit(*(context->pointer)))
            (context->pointer)++;
        context->token = icsStrndup(anchor, context->pointer - anchor);
        iecSINT *endptr = NULL;
        context->value = newValue3(SPVT_NUMERIC, strtod(context->token, &endptr), NULL);
        return context->type = SPTT_NUMBER;
    }

    if((!ignoreSign && (c1 == '+' || c1 == '-') && (isdigit(c2) || c2 == '.')) ||
       isdigit(c1) ||
       (c1 == '.' && isdigit(c2))) {

        if((c1 == '+' || c1 == '-'))
            (context->pointer)++;
        while(isdigit(*(context->pointer)) || *(context->pointer) == '.')
            (context->pointer)++;
        if(*(context->pointer) == 'e' || *(context->pointer) == 'E') {
            (context->pointer)++;
            if((*(context->pointer)  == '+' || *(context->pointer)  == '-'))
                (context->pointer)++;
            while(isdigit(*(context->pointer)))
                (context->pointer)++;
        }
        context->token = icsStrndup(anchor, context->pointer - anchor);
        iecSINT *endptr = NULL;
        context->value = newValue3(SPVT_NUMERIC, strtod(context->token, &endptr), NULL);
        return context->type = SPTT_NUMBER;
    }

    if(c2 == '=') {
        switch(c1) {
            case '=': context->type = SPTT_EQ;         break;
            case '<': context->type = SPTT_LE;         break;
            case '>': context->type = SPTT_GE;         break;
            case '!': context->type = SPTT_NE;         break;
            case '+': context->type = SPTT_ASSIGN_ADD; break;
            case '&': context->type = SPTT_ASSIGN_CAT; break;
            case '-': context->type = SPTT_ASSIGN_SUB; break;
            case '*': context->type = SPTT_ASSIGN_MUL; break;
            case '/': context->type = SPTT_ASSIGN_DIV; break;
            default:  context->type = SPTT_NONE;       break;
        }

        if(context->type != SPTT_NONE) {
            context->token = icsStrndup(anchor, 2);
            context->pointer += 2;
            return context->type;
        }
    }

    switch(c1) {

        case '\'': {
            iecSINT *word = extractQuotedString(&(context->pointer));
            if(word == NULL)
                return context->type = SPTT_END; // unterminated string
            context->value = newValue3(SPVT_STRING, 0.0, word);
            return context->type = SPTT_STRING;
        }
        break;

        case '&':
        if(c2 == '&') {
            context->token = icsStrndup(anchor, 2);
            context->pointer += 2;
            return context->type = SPTT_AND;
        }
        else {
            context->token = icsStrndup(anchor, 1);
            (context->pointer)++;
            return context->type = SPTT_BITAND;
        }
        break;

        case '|':
        if(c2 == '|') {
            context->token = icsStrndup(anchor, 2);
            context->pointer += 2;
            return context->type = SPTT_OR;
        }
        else {
            context->token = icsStrndup(anchor, 1);
            (context->pointer)++;
            return context->type = SPTT_BITOR;
        }
        break;

        case '>':
        if(c2 == '>') {
            context->token = icsStrndup(anchor, 2);
            context->pointer += 2;
            return context->type = SPTT_BITSHR;
        }
        else {
            context->token = icsStrndup(anchor, 1);
            (context->pointer)++;
            return context->type = SPTT_GT;
        }
        break;

        case '<':
        if(c2 == '<') {
            context->token = icsStrndup(anchor, 2);
            context->pointer += 2;
            return context->type = SPTT_BITSHL;
        }
        else {
            context->token = icsStrndup(anchor, 1);
            (context->pointer)++;
            return context->type = SPTT_LT;
        }
        break;

        case '=':
        case '!':
        case '+':
        case '-':
        case '/':
        case '*':
        case '(':
        case ')':
        case ',':
        case '^':
        case '~':
        case '[':
        case ']':
        context->token = icsStrndup(anchor, 1);
        (context->pointer)++;
        return context->type = (IcsPredicateTokenType) c1;
    }

    if(!isalpha(c1))
        return context->type = SPTT_END; // Unexpected character

    while(isalnum(*(context->pointer)) || *(context->pointer) == '_' || *(context->pointer) == '.')
        (context->pointer)++;

    context->token = icsStrndup(anchor, context->pointer - anchor);
    return context->type = SPTT_NAME;
}

static IcsPredicateValue *primary(IcsPredicateParseContext *context)
{
    getToken(context, iecFALSE);

    switch(context->type) {
        case SPTT_NUMBER: {
            IcsPredicateValue *v = context->value;
            context->value = NULL;
            getToken(context, iecTRUE);
            return v;
        }

        case SPTT_STRING: {
            IcsPredicateValue *v = context->value;
            context->value = NULL;
            getToken(context, iecTRUE);
            return v;
        }

        case SPTT_NAME: {
            iecSINT *name = icsStrdup(context->token);
            getToken(context, iecTRUE);

            if(context->type == SPTT_LHPAREN) {
                // find function name
                // get args with Expression()
                // grab args using (COMMA) until checkToken(RHPAREN)
                ICS_FREE(name);
                getToken(context, iecTRUE);
                return newValue4(SPVT_NONE, 0.0, NULL);
            }

            IcsPredicateValue *v = getSymbol(context, name);
            switch(context->type) {
                case SPTT_ASSIGN:     setValue(v, expression(context)); setSymbol(context, name, v); break;
                case SPTT_ASSIGN_CAT: catValue(v, expression(context)); setSymbol(context, name, v); break;
                case SPTT_ASSIGN_ADD: addValue(v, expression(context)); setSymbol(context, name, v); break;
                case SPTT_ASSIGN_SUB: subValue(v, expression(context)); setSymbol(context, name, v); break;
                case SPTT_ASSIGN_MUL: mulValue(v, expression(context)); setSymbol(context, name, v); break;
                case SPTT_ASSIGN_DIV: divValue(v, expression(context)); setSymbol(context, name, v); break;
                default: break;
            }
            ICS_FREE(name);
            return v;
        }

        case SPTT_MINUS:    return negValue(primary(context));
        case SPTT_NOT:      return invValue(primary(context));
        case SPTT_BITINV:   return bivValue(primary(context));

        case SPTT_LBRACKET: {
            IcsPredicateValue *v = array(context);
            if(!checkToken(context, SPTT_RBRACKET)) {
                icsFreePredicateValue(&v);
                return newValue4(SPVT_NONE, 0.0, NULL);
            }
            getToken(context, iecTRUE);
            return v;
        }

        case SPTT_LHPAREN: {
            IcsPredicateValue *v = commaList(context);
            if(!checkToken(context, SPTT_RHPAREN))
                return newValue4(SPVT_NONE, 0.0, NULL);
            getToken(context, iecTRUE);
            return v;
        }
        default:    break; // Unexpected token
    }
    return newValue4(SPVT_NONE, 0.0, NULL);
}

static IcsPredicateValue *term(IcsPredicateParseContext *context)
{
    IcsPredicateValue *v = primary(context);
    while(v->type != SPVT_NONE) {
        switch(context->type) {
            case SPTT_MULTIPLY: mulValue(v, primary(context)); break;
            case SPTT_DIVIDE:   divValue(v, primary(context)); break;
            default:            return v;
        }
    }
    return v;
}

static IcsPredicateValue *bitWise(IcsPredicateParseContext *context)
{
    IcsPredicateValue *v = term(context);
    while(v->type != SPVT_NONE) {
        switch(context->type) {
            case SPTT_BITAND: banValue(v, term(context)); break;
            case SPTT_BITOR:  borValue(v, term(context)); break;
            case SPTT_BITXOR: bxrValue(v, term(context)); break;
            case SPTT_BITSHL: shlValue(v, term(context)); break;
            case SPTT_BITSHR: shrValue(v, term(context)); break;
            default:         return v;
        }
    }
    return v;
}

static IcsPredicateValue *addSubtract(IcsPredicateParseContext *context)
{
    IcsPredicateValue *v = bitWise(context);
    while(v->type != SPVT_NONE) {
        switch(context->type) {
            case SPTT_CAT:   catValue(v, bitWise(context)); break;
            case SPTT_PLUS:  addValue(v, bitWise(context)); break;
            case SPTT_MINUS: subValue(v, bitWise(context)); break;
            default:         return v;
        }
    }
    return v;
}

static IcsPredicateValue *comparison(IcsPredicateParseContext *context)
{
    IcsPredicateValue *v = addSubtract(context);
    while(v->type != SPVT_NONE) {
        switch(context->type) {
            case SPTT_LT: bltValue(v, addSubtract(context)); break;
            case SPTT_GT: bgtValue(v, addSubtract(context)); break;
            case SPTT_LE: bleValue(v, addSubtract(context)); break;
            case SPTT_GE: bgeValue(v, addSubtract(context)); break;
            case SPTT_EQ: beqValue(v, addSubtract(context)); break;
            case SPTT_NE: bneValue(v, addSubtract(context)); break;
            case SPTT_IN: ainValue(v, addSubtract(context)); break;
            default:      return v;
        }
    }
    return v;
}

static IcsPredicateValue *expression(IcsPredicateParseContext *context)
{
    IcsPredicateValue *v = comparison(context);
    while(v->type != SPVT_NONE) {
        switch(context->type) {
            case SPTT_AND: andValue(v, comparison(context)); break;
            case SPTT_OR:  rorValue(v, comparison(context)); break;
            default:       return v;
        }
    }
    return v;
}

static IcsPredicateValue *array(IcsPredicateParseContext *context)
{
    IcsPredicateValue *a = icsCreatePredicateArray();
    IcsPredicateValue *v = expression(context);
    icsAppendPredicateValue(a, v);
    while(context->type == SPTT_COMMA)
        icsAppendPredicateValue(a, expression(context));
    return a;
}

static IcsPredicateValue *commaList(IcsPredicateParseContext *context)
{
    IcsPredicateValue *v = expression(context);
    while(context->type == SPTT_COMMA) {
        icsFifoPush(context->output, v);
        v = expression(context);
    }
    return v;
}

static IcsPredicateValue *evaluate(IcsPredicateParseContext *context)
{
    IcsPredicateValue *v = commaList(context);
    if(v == NULL || v->type != SPVT_NONE)
        return v;
    if(context->type == SPTT_END)
        coerceValue(v, SPVT_NONE);
    return v;
}

static IcsPredicateParseContext *createParseContext(iecSINT *predicate, IcsHash *globals, IcsHash *constants, IcsHash *variables)
{
    ICS_TMEMORY(context, IcsPredicateParseContext);
    if(context != NULL) {
        context->type      = SPTT_NONE;
        context->predicate = icsStrdup(predicate);
        context->pointer   = context->predicate;
        context->globals   = globals;
        context->constants = constants;
        context->variables = variables;
        context->locals    = icsHashCreate(1024, 90, SCHA_DEFAULT);
        context->output    = icsFifoCreate();
    }
    return context;
}

static void freeParseContext(IcsPredicateParseContext *context)
{
    if(context != NULL) {
        ICS_FREE(context->predicate);
        icsFreePredicateHash(context->locals);
        icsFifoFree(context->output);
        ICS_FREE(context);
    }
}

IcsFifo *icsPredicateEvaluate(iecSINT *predicate, IcsHash *globals, IcsHash *constants, IcsHash *variables)
{
    if(predicate == NULL)
        return NULL;
    IcsFifo *output = NULL;
    IcsPredicateParseContext *context = createParseContext(predicate, globals, constants, variables);
    if(context != NULL) {
        IcsPredicateValue *v = evaluate(context);
        if(v != NULL) {
            output = context->output;
            icsFifoPush(output, v);
        }
        else {
            IcsPredicateValue *poppedV;
            while((poppedV = icsFifoPop(context->output)) != NULL)
                icsFreePredicateValue(&poppedV);
        }
        context->output = NULL;
        freeParseContext(context);
    }
    return output;
}

IcsPredicateValue *icsCreatePredicateValue(IcsPredicateValueType type, iecLREAL d, const iecSINT *s)
{
    return newValue(type, d, s);
}

IcsPredicateValue *icsCreatePredicateString(const iecSINT *s)
{
    return icsCreatePredicateValue(SPVT_STRING, 0, s);
}

IcsPredicateValue *icsCreatePredicateNumber(iecLREAL d)
{
    return icsCreatePredicateValue(SPVT_NUMERIC, d, NULL);
}

IcsPredicateValue *icsCreatePredicateArray(void)
{
    return icsCreatePredicateValue(SPVT_ARRAY, 0, NULL);
}

IcsPredicateValue *icsEmptyPredicateArray(IcsPredicateValue *array)
{
    if(array != NULL && array->type == SPVT_ARRAY)
        icsFreePredicateValue(&(array->next));
    return array;
}

IcsPredicateValue *icsAppendPredicateValue(IcsPredicateValue *array, IcsPredicateValue *value)
{
    if(array != NULL && value != NULL && array->type == SPVT_ARRAY) {
        IcsPredicateValue *root = array;
        int count = 0;
        while(array != NULL) {
            if(array->next == NULL) {
                root->count = ++count;
                return array->next = value;
            }
            array = array->next;
            count++;
        }
    }
    return NULL;
}

void icsFreePredicateHash(IcsHash *h)
{ return;
    if(h != NULL) {
        iecSINT *key;
        IcsPredicateValue *v = icsHashFirstItem(h, &key);
        while(v != NULL) {
            v = icsHashDeleteItem(h, key);
            icsFreePredicateValue(&v);
            v = icsHashNextItem(h, &key);
        }
        icsHashFree(h);
    }
}

void icsFreePredicateValue(IcsPredicateValue **pv)
{
    if(pv == NULL || *pv == NULL)
        return;
    IcsPredicateValue *v = *pv;
    IcsPredicateValue *root = v;
    IcsPredicateValue *prev = root;
    while(v != NULL) {
        if(v->next == NULL) {
            prev->next = NULL;
            ICS_FREE(v->s);
            ICS_FREE(v);
            *pv = NULL;
            return;
        }
        prev->next = v->next;
        if(root == v)
            root = v->next;
        ICS_FREE(v->s);
        ICS_FREE(v);
        v = prev->next;
    }
    *pv = (prev != root ? prev : NULL);
}

IcsPredicateValue *icsNumberArrayFromKeywordParameters(const iecSINT *parameters, IcsNumericAssociation *table)
{
    IcsPredicateValue *array = NULL;
    char **oo = icsRxSplit(parameters, "/\\s*,\\s*/");
    if(oo != NULL && (array = icsCreatePredicateArray()) != NULL) {
        for(int i = 0; oo[i] != NULL; i++) {
            iecBOOL found = iecFALSE;
            iecUDINT item = 0;
            if(table != NULL) {
                for(int j = 0; !found && table[j].name != NULL; j++) {
                    if(stricmp(oo[i], table[j].name) == 0) {
                        item = table[j].value;
                        found = iecTRUE;
                    }
                }
            }
            if(!found) {
                iecSINT *endptr = NULL;
                item = (iecUDINT) strtol(oo[i], &endptr, 0);
                if(table != NULL && *endptr != '\0') {
                    icsLog(ICS_LOGLEVEL_ERROR, "invalid keyword '%s' in signature", oo[i]);
                    continue;
                }
            }
            icsAppendPredicateValue(array, icsCreatePredicateNumber(item));
        }
        icsFreeStringArray(oo);
    }
    return array;
}

IcsPredicateValue *icsStringArrayFromKeywordParameters(const iecSINT *parameters)
{
    IcsPredicateValue *array = NULL;
    char **oo = icsRxSplit(parameters, "/\\s*,\\s*/");
    if(oo != NULL && (array = icsCreatePredicateArray()) != NULL) {
        for(int i = 0; oo[i] != NULL; i++) {
            IcsPredicateValue *item = icsCreatePredicateString(oo[i]);
            if(item != NULL)
                icsAppendPredicateValue(array, item);
        }
        icsFreeStringArray(oo);
    }
    return array;
}

IcsPredicateValue *icsBitfieldFromKeywordParameters(const iecSINT *parameters, IcsNumericAssociation *table)
{
    IcsPredicateValue *bitfield = NULL;
    char **oo = icsRxSplit(parameters, "/\\s*\\|\\s*/");
    if(oo != NULL) {
        iecUDINT bits = 0;
        for(int i = 0; oo[i] != NULL; i++) {
            iecBOOL found = iecFALSE;
            iecUDINT item = 0;
            if(table != NULL) {
                for(int j = 0; !found && table[j].name != NULL; j++) {
                    if(stricmp(oo[i], table[j].name) == 0) {
                        item = table[j].value;
                        found = iecTRUE;
                    }
                }
            }
            if(!found) {
                iecSINT *err = NULL;
                item = (iecUDINT) strtol(oo[i], &err, 0);
            }
            bits |= item;
        }
        bitfield = icsCreatePredicateNumber(bits);
        icsFreeStringArray(oo);
    }
    return bitfield;
}

IcsPredicateValue *icsGetPredicateArrayItem(IcsPredicateValue *array, iecUINT index)
{
    if(array == NULL || array->type != SPVT_ARRAY)
        return NULL;
    iecUINT i;
    IcsPredicateValue *current = NULL;
    for(current = array->next; current != NULL; current = current->next)
        if(index == i++)
            break;
    return dupeValue(current);
}

IcsPredicateValue *icsFindPredicateArrayNumberItem(IcsPredicateValue *array, iecLREAL d)
{
    if(array == NULL || array->type != SPVT_ARRAY)
        return NULL;
    IcsPredicateValue *current = NULL;
    for(current = array->next; current != NULL &&  current->type == SPVT_NUMERIC; current = current->next)
        if(current->d == d)
            break;
    return dupeValue(current);
}

IcsPredicateValue *icsFindPredicateArrayStringItem(IcsPredicateValue *array, const iecSINT *s)
{
    if(array == NULL || array->type != SPVT_ARRAY)
        return NULL;
    IcsPredicateValue *current = NULL;
    for(current = array->next; current != NULL && current->type == SPVT_STRING; current = current->next)
        if(strcmp(current->s, s) == 0)
            break;
    return dupeValue(current);
}
