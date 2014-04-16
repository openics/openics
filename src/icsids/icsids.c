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
#define SYSLOG_NAMES
#include "icsids.h"
#include "icsids-process.h"
#include "icsids-args.h"

static int makeSomeNoise = 0;
static int pinnedPortCount = 0;
static uint16_t pinnedPorts[MAX_PINNED_PORTS];
static time_t mrT = 0;
static int syslogFacility;
static IcsScenario *root[ICS_PROTO_ALL];

static char *describeFlow(int proto, uint32_t srcIp, uint16_t srcPort, uint32_t dstIp, uint16_t dstPort, char *s, int max)
{
    snprintf(s, max, "%d %d.%d.%d.%d %d %d.%d.%d.%d %d", proto,
             (srcIp >> 24) & 0xff, (srcIp >> 16) & 0xff, (srcIp >> 8) & 0xff, srcIp & 0xff, srcPort,
             (dstIp >> 24) & 0xff, (dstIp >> 16) & 0xff, (dstIp >> 8) & 0xff, dstIp & 0xff, dstPort);
    return s;
}

static void handletcp(struct tcp_stream *ts, StreamFlag flag)
{
    unsigned long srcBytes = ts->client.count - ts->client.offset;
    if(srcBytes > 0) { // request
        iecBYTE *data = (iecBYTE *) (ts->client.data + ts->client.offset);
        if(ts->user == NULL) { // we have no state, so let's detect
            IcsProtocol proto = icsProbe(ICS_LAYER_APPLICATION, ICS_PROTO_DETECT, data, srcBytes); 
            if(proto != ICS_PROTO_NONE) {
                IcsStack *stack = ts->user = icsStackAllocate();
                stack->application.primaryProtocol = proto;
            }
        }
        if(ts->user != NULL) {
            IcsStack *stack = ts->user;
            IcsParseResult r = icsParse(ICS_LAYER_APPLICATION, stack->application.primaryProtocol, ICS_MODE_RQ, data, srcBytes, stack); 
            if(r != ICS_RESULT_OK) {
                // emit parser error
            }
        }
    }

    unsigned long dstBytes = ts->server.count - ts->server.offset;
    if(dstBytes > 0) { // response
        iecBYTE *data = (iecBYTE *) (ts->server.data + ts->server.offset);
        if(ts->user != NULL) {
            IcsStack *stack = ts->user;
            IcsParseResult r = icsParse(ICS_LAYER_APPLICATION, stack->application.primaryProtocol, ICS_MODE_RS, data, dstBytes, stack); 
            if(r != ICS_RESULT_OK) {
                // emit parser error
            }
            IcsScenario *curr = root[stack->application.primaryProtocol];
            while(curr != NULL) {
                IcsTransaction *transaction = icsTransactionPop(stack, stack->application.primaryProtocol);
                if(transaction != NULL) {
                    if(icsEvaluate(curr->di, transaction)) {
                        char desc[MAX_FLOW_DESCRIPTION];
                        syslog(curr->priority, "%s %s '%s' '%s'", describeFlow(0x06, ntohl(ts->addr.saddr), ts->addr.source, ntohl(ts->addr.daddr), ts->addr.dest, desc, sizeof(desc)), curr->proto, curr->cve, curr->description);
                    }
                    icsTransactionFree(transaction);
                }
                curr = curr->next;
            }
        }
    }

    if(flag >= StreamFlagClose) { // non-data packets
        if(ts->user != NULL) {
            IcsStack *stack = ts->user;
            icsStackFree(stack);
            ts->user = NULL;
        }
    }
}

static int pinned(uint16_t port)
{
    for(int i=0; i < pinnedPortCount; i++)
        if(port == pinnedPorts[i])
            return 1;
    return 0;
}

static void tcp_resume(struct tcphdr *tcphdr, struct ip *iphdr, int *pResume)
{
    if(pinned(ntohs(tcphdr->th_sport)))
        *pResume = NIDS_TCP_RESUME_SERVER;
    else
    if(pinned(ntohs(tcphdr->th_dport)))
        *pResume = NIDS_TCP_RESUME_CLIENT;
}

static void tcp(struct tcp_stream *ts, void **opaque)
{
    char desc[MAX_FLOW_DESCRIPTION];
    switch(ts->nids_state) {
        case NIDS_JUST_EST: {
            if(makeSomeNoise > 1)
                syslog(LOG_DEBUG, "nids-tcp-established - %s", describeFlow(0x06, ntohl(ts->addr.saddr), ts->addr.source, ntohl(ts->addr.daddr), ts->addr.dest, desc, sizeof(desc)));
            ts->client.collect = 1;
            ts->server.collect = 1;
            handletcp(ts, StreamFlagFirst);
        } break;
        case NIDS_RESUME: {
            if(makeSomeNoise > 1)
                syslog(LOG_DEBUG, "nids-tcp-midstream - %s", describeFlow(0x06, ntohl(ts->addr.saddr), ts->addr.source, ntohl(ts->addr.daddr), ts->addr.dest, desc, sizeof(desc)));
            ts->client.collect = 1;
            ts->server.collect = 1;
            handletcp(ts, StreamFlagFirst);
        } break;
        case NIDS_DATA: {
            if(makeSomeNoise > 1)
                syslog(LOG_DEBUG, "nids-tcp-data - %s", describeFlow(0x06, ntohl(ts->addr.saddr), ts->addr.source, ntohl(ts->addr.daddr), ts->addr.dest, desc, sizeof(desc)));
            handletcp(ts, StreamFlagData);
        } break;
        case NIDS_CLOSE: {
            if(makeSomeNoise > 1)
                syslog(LOG_DEBUG, "nids-tcp-close - %s", describeFlow(0x06, ntohl(ts->addr.saddr), ts->addr.source, ntohl(ts->addr.daddr), ts->addr.dest, desc, sizeof(desc)));
            handletcp(ts, StreamFlagClose);
        } break;
        case NIDS_RESET: {
            if(makeSomeNoise > 1)
                syslog(LOG_DEBUG, "nids-tcp-reset - %s", describeFlow(0x06, ntohl(ts->addr.saddr), ts->addr.source, ntohl(ts->addr.daddr), ts->addr.dest, desc, sizeof(desc)));
            handletcp(ts, StreamFlagReset);
        } break;
        case NIDS_TIMED_OUT: {
            if(makeSomeNoise > 1)
                syslog(LOG_DEBUG, "nids-tcp-timedout - %s", describeFlow(0x06, ntohl(ts->addr.saddr), ts->addr.source, ntohl(ts->addr.daddr), ts->addr.dest, desc, sizeof(desc)));
            handletcp(ts, StreamFlagTimeout);
        } break;
        case NIDS_EXITING: {
            if(makeSomeNoise > 1)
                syslog(LOG_DEBUG, "nids-tcp-exiting - %s", describeFlow(0x06, ntohl(ts->addr.saddr), ts->addr.source, ntohl(ts->addr.daddr), ts->addr.dest, desc, sizeof(desc)));
            handletcp(ts, StreamFlagExit);
        } break;
        default: {
            if(makeSomeNoise > 1)
                syslog(LOG_DEBUG, "nids-tcp-unknown - %s", describeFlow(0x06, ntohl(ts->addr.saddr), ts->addr.source, ntohl(ts->addr.daddr), ts->addr.dest, desc, sizeof(desc)));
        } break;
    }
}

static void nidsSyslog(int type, int errnum, struct ip *iph, void *data)
{
    if(makeSomeNoise)
        syslog(LOG_DEBUG, "nids-error - %d", errnum);
}

static int startNids(int streams, int hosts)
{   
    int r = 0;
    if((nids_params.pcap_desc = pcap_open_dead(DLT_EN10MB, 64535)) != NULL) {
        nids_params.syslog = nidsSyslog;
        nids_params.n_tcp_streams = streams;
        nids_params.n_hosts = hosts;
        nids_params.scan_num_hosts = 0;
        if((r = nids_init()) != 0) {
            nids_register_tcp(tcp);
            nids_register_tcp_resume(tcp_resume);

            static struct nids_chksum_ctl chkctl;
            chkctl.netaddr  = 0;
            chkctl.mask     = 0;
            chkctl.action   = 1;
            chkctl.reserved = 0;
            nids_register_chksum_ctl(&chkctl, 1);
        }
    }
    return r;
}

static void enqueue(uint8_t *opaque, struct pcap_pkthdr *h, uint8_t *bytes)
{
    void queue(IcsQueue *q, struct pcap_pkthdr *h, uint8_t *bytes) {
        size_t sz = sizeof(struct pcap_pkthdr) + h->caplen;
        struct pcapbundle *bundle = (struct pcapbundle *) malloc(sz);
        if(bundle != NULL) {
            memcpy(&(bundle->h), h, sizeof(struct pcap_pkthdr));
            memcpy(bundle->p, bytes, h->caplen);
            icsQueueAddItem(q, bundle, -1);
        }
    }
    IcsState *state = (IcsState *) opaque;
    queue(state->packets, h, bytes);
}

static void *dequeue(void *opaque)
{
    setAffinity(1);
    IcsState *state = opaque;
    while(state != NULL) {
        size_t sz;
        struct pcapbundle *bundle = icsQueueGetItem(state->packets, &sz);
        if(bundle != NULL) {
            mrT = bundle->h.ts.tv_sec; // hack-ish
            nids_pcap_handler((uint8_t *) state, &(bundle->h), bundle->p);
            ICS_FREE(bundle);
        }
        else 
            delay(IDLE_DELAY);
    }
    return NULL;
}

static pcap_t *pcap_open_offline_buffered(const char *path, char *buffer, size_t size, char *errbuf)
{
    FILE *fp;
    if(strcmp(path, "-") == 0)
        fp = stdin;
    else
    if((fp = fopen(path, "rb")) == NULL) {
        strcpy(errbuf, "file not found");
        return NULL;
    }
    setvbuf(fp, buffer, _IOFBF, size);
    pcap_t *pcap = pcap_fopen_offline(fp, errbuf);
    if(pcap != NULL)
        pcap_set_snaplen(pcap, 0xffff);
    return pcap;
}

static void freeIcsState(IcsState **state)
{
    syslog(LOG_INFO, "shutting down");
    IcsState *s = *state;
    if(s != NULL) {
        if(s->rvbuf != NULL)
            ICS_FREE(s->rvbuf);
        if(s->pcap != NULL)
            pcap_close(s->pcap);
        if(s->packets != NULL) {
            if(s->packets->max > 0) {
                while(!icsQueueIsEmpty(s->packets))
                    delay(1);
            }
            syslog(LOG_INFO, "queue high water mark: %lu", s->packets->max);
            icsQueueFree(s->packets);
            s->packets = NULL;
        }
        if(s->dequeueThread != 0) {
            pthread_detach(s->dequeueThread);
            pthread_cancel(s->dequeueThread);
            sleep(1);
        }
        ICS_FREE(*state);
        *state = NULL;
    }
}

static void loadPinnedPorts(char *pinnedPortSpec)
{
    char *saveptr = NULL;
    char *pp = strdup(pinnedPortSpec);
    char *pin = strtok_r(pp, ",", &saveptr);
    for(pinnedPortCount=0; pin != NULL && pinnedPortCount < MAX_PINNED_PORTS; pinnedPortCount++) {
        pinnedPorts[pinnedPortCount] = (unsigned) atoi(pin);
        pin = strtok_r(NULL, ",", &saveptr);
    }
    ICS_FREE(pp);
}

static IcsState *createIcsState(char *inputfile, char *interface, int promisc, int maxSessions, int maxHosts, int rvbSz)
{
    if(inputfile == NULL && interface == NULL)
        interface = "all";
    int r = -1;
    IcsState *state = malloc(sizeof(IcsState));
    if(state != NULL) {
        memset(state, 0, sizeof(IcsState));
        char errbuf[PCAP_ERRBUF_SIZE];
        if((state->packets = icsQueueCreate(32768, 60)) != NULL) {
            if((state->rvbuf = malloc(rvbSz)) != NULL) {
                if(interface != NULL) {
                    state->pcap = pcap_open_live(interface, 65535, promisc, 0, errbuf);
                    if(state->pcap != NULL)
                        syslog(LOG_INFO, "initiated capture from interface '%s'", interface);
                }
                else
                if(inputfile != NULL) {
                    state->pcap = pcap_open_offline_buffered(inputfile, state->rvbuf, rvbSz, errbuf);
                    if(state->pcap != NULL)
                        syslog(LOG_INFO, "initiated capture from input file '%s'", inputfile);
                }
                if(state->pcap != NULL) {
                    if(startNids(maxSessions, maxHosts))
                        r = pthread_create(&(state->dequeueThread), NULL, dequeue, state);
                }
                else
                    syslog(LOG_ERR, "unable to initiate capture");
            }
        }
    }
    if(r != 0) 
        freeIcsState(&state);
    return state;
}

static int translateProtocol(const char *protocol)
{
    if(strcmp(protocol, "cip") == 0)
        return ICS_PROTO_CIP;
    else
    if(strcmp(protocol, "enip") == 0)
        return ICS_PROTO_ENIP;
    else
    if(strcmp(protocol, "dnp3") == 0)
        return ICS_PROTO_DNP3;
    else
    if(strcmp(protocol, "modbus") == 0)
        return ICS_PROTO_MODBUS;
    return ICS_PROTO_NONE;
}

static int translateFacility(const char *facilityStr)
{
    int facility = -1;
    if(facilityStr != NULL)
        for(int i=0; facility == -1 && facilitynames[i].c_name != NULL; i++)
            if(stricmp(facilityStr, facilitynames[i].c_name) == 0)
                facility = facilitynames[i].c_val;
    return facility;
}

static int translatePriority(const char *priorityStr)
{
    int priority = -1;
    if(priorityStr != NULL)
        for(int i=0; priority == -1 && prioritynames[i].c_name != NULL; i++)
            if(stricmp(priorityStr, prioritynames[i].c_name) == 0)
                priority = prioritynames[i].c_val;
    return priority;
}

static int loadScenarios(IcsScenario **scenarioRoot, char *scenarioDir)
{
    char scenarioMask[PATH_MAX];
    snprintf(scenarioMask, PATH_MAX, "%s/*.*.ics", scenarioDir);
    syslog(LOG_INFO, "scenario mask %s", scenarioMask);
    glob_t gl;
    memset(&gl, 0, sizeof(glob_t));
    IcsScenario *curr[ICS_PROTO_ALL];
    memset(curr, 0, sizeof(IcsScenario *) * ICS_PROTO_ALL);
    int count = 0;
    int r = glob(scenarioMask, 0, NULL, &gl);
    if(r == 0) {
        for(int i=0; i < gl.gl_pathc; i++) {
            FILE *fp = fopen(gl.gl_pathv[i], "r");
            if(fp != NULL) {
                char buffer[4096];
                while(fgets(buffer, 4096, fp)) {
                    if(!(buffer[0] >= 'a' && buffer[0] <= 'z') &&
                       !(buffer[0] >= 'A' && buffer[0] <= 'Z'))
                        continue;
                    buffer[strlen(buffer)-1] = '\0';
                    char *proto = buffer;
                    char *prior = strchr(proto, '\t');
                    if(prior == NULL)
                        continue;
                    *prior++ = '\0';
                    char *cve = strchr(prior, '\t');
                    if(cve == NULL)
                        continue;
                    *cve++ = '\0';
                    char *description = strchr(cve, '\t');
                    if(description == NULL)
                        continue;
                    *description++ = '\0';
                    char *predicate = strchr(description, '\t');
                    if(predicate == NULL)
                        continue;
                    *predicate++ = '\0';

                    IcsProtocol protocol = translateProtocol(proto);
                    if(protocol == ICS_PROTO_NONE) {
                        syslog(LOG_ERR, "unsupported protocol '%s' (%s)", proto, description);
                        continue;
                    }

                    int priority = translatePriority(prior);
                    if(priority == -1) {
                        syslog(LOG_ERR, "unsupported priority %s (%s)", prior, description);
                        continue;
                    }

                    ICS_TMEMORY(t, IcsScenario);
                    t->protocol    = protocol;
                    t->priority    = priority;
                    t->proto       = icsStrdup(proto);
                    t->cve         = icsStrdup(cve);
                    t->description = icsStrdup(description);
                    t->di          = icsMunge(proto, predicate);

                    syslog(LOG_DEBUG, "accepted scenario %s(%d) %s(%d) %s %s %s", proto, protocol, prior, priority, t->cve, t->description, predicate);

                    if(root[protocol] == NULL)
                        curr[protocol] = root[protocol] = t;
                    else
                        curr[protocol] = curr[protocol]->next = t;

                    count++;
                }
                fclose(fp);
            }
        }
        globfree(&gl);
    }
    return count;
}

static void freeScenarios(IcsScenario **scenarioRoot)
{
    for(int i=0; i < ICS_PROTO_ALL; i++) {
        IcsScenario *curr = scenarioRoot[i];
        while(curr != NULL) {
            IcsScenario *t = curr->next;
            ICS_FREE(curr->proto);
            ICS_FREE(curr->cve);
            ICS_FREE(curr->description);
            icsFreeDetectItem(curr->di);
            ICS_FREE(curr);
            curr = t;
        }
        scenarioRoot[i] = NULL;
    }
}

static IcsState *signalState = NULL;
static void termfcn(int signo)
{
    if(signalState != NULL)
        pcap_breakloop(signalState->pcap);
}

int main(int argc, char **argv)
{
    Args *a = getArgs(argc, argv);
    if(a == NULL) 
        return -1;

    makeSomeNoise = a->debug;

    int syslogMode = LOG_PID;
    if(!a->detach)
        syslogMode |= LOG_PERROR;

    syslogFacility = LOG_USER;
    if(a->facility != NULL) {
        int slf = translateFacility(a->facility);
        if(slf == -1) {
            fprintf(stderr, "Invalid facility '%s'\n", a->facility);
            return -2;
        }
        syslogFacility = slf;
    }

    openlog("icsids", syslogMode, syslogFacility);
    syslog(LOG_INFO, "starting up");

    if(!loadScenarios(root, a->scenarioDir)) {
        syslog(LOG_ERR, "failed to load any scenarios");
        return -3;
    }

    setAffinity(0);
    signalSetup(3, termfcn);
    if(a->pinnedlist != NULL)
        loadPinnedPorts(a->pinnedlist);

    if(a->detach && detach("icsids", a->chroot, a->user, a->group) == 0) {
        syslog(LOG_ERR, "failed to detach");
        return -4;
    }

    if(icsInitialize(NULL, NULL, NULL)) {
        IcsState *state = signalState = createIcsState(a->inputfile, a->interface, a->promisc, a->maxsessions, a->maxhosts, 8192);
        if(state != NULL) {
            pcap_loop(state->pcap, 0, (pcap_handler) enqueue, (uint8_t *) state);
            freeIcsState(&state);
        }
        icsUninitialize();
    }

    freeScenarios(root);

    freeArgs(a);

    closelog();

    return 0;
}

