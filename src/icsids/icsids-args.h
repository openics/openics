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
#if !defined(_icsids_args_h)
#define _icsids_args_h

#define __USE_GNU
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_SCENARIO_DIR	"/etc/ics/scenario.d"

typedef struct tagArgs {
    char *inputfile;    // -r
    char *interface;    // -i
    char *pinnedlist;   // -l
	char *scenarioDir;  // -S
	char *user;			// -u
	char *group;		// -g
	char *facility;     // -f
	char *chroot;       // -R
    char *filter;       //
	int detach;			// -d
	int debug; 			// -D
    int promisc;        // -p
    int maxsessions;    // -s
    int maxhosts;       // -H
} Args;

Args *getArgs(int argc, char **argv);
void freeArgs(Args *args);

#endif

