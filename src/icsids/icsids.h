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
#if !defined(_icsids_h)
#define _icsids_h

#include <pcap/pcap.h>
#include <pcap-bpf.h>

#define __USE_GNU
#include <sched.h>

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <errno.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sched.h>
#include <pwd.h>
#include <grp.h>
#include <limits.h>
#include <syscall.h>
#include <signal.h>
#include <glob.h>

#define __USE_XOPEN_EXTENDED
#include <pthread.h>

#if !defined(gettid)
    #define gettid() syscall(__NR_gettid)
#else
    #define gettid() 1
#endif

#ifndef ENABLE_TCPREASM
	#define ENABLE_TCPREASM
#endif
#include <nids.h>

#include <ics.h>

#define MAX_FLOW_DESCRIPTION	128
#define MAX_PINNED_PORTS		1024
#define IDLE_DELAY				1000000000

typedef enum tagStreamFlag {
    StreamFlagStateless = 0,
    StreamFlagFirst,
    StreamFlagDataIn,
    StreamFlagDataOut,
    StreamFlagData,
    StreamFlagClose,
    StreamFlagReset,
    StreamFlagTimeout,
    StreamFlagExit
} StreamFlag;

typedef struct tagIcsState {
	IcsQueue  *packets;
	char      *rvbuf;
    char      pcapError[PCAP_ERRBUF_SIZE];
	pcap_t    *pcap;
	pthread_t dequeueThread;
} IcsState;

typedef struct tagIcsScenario {
	int   protocol;
	int   priority;
	char *proto;
	char *cve;
	char *description;
	IcsDetectItem *di;
	struct tagIcsScenario *next;
} IcsScenario;

struct pcapbundle {
    struct pcap_pkthdr h;
    u_char p[];
};

#endif
