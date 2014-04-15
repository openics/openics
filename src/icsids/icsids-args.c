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
#include "icsids.h"
#include "icsids-args.h"

void usage()
{
	fprintf(stderr, "\nusage:\n\n"
                    "icsids -S scenario-dir    - directory where scenario files are found\n"
                    "       -r input-pcap-file - read packets from input-pcap-file and exit\n"
                    "       -i interface       - source packets from specified interface\n"
                    "       -l pin-list        - for mid-stream sessions, treat ports in list as dest ports\n"
                    "       -s max-sessions    - maximum sessions for libnids to track (default 8192)\n"
                    "       -H max-hosts       - maximum hosts for libnids to track (default 1024)\n"
					"       -u run-as-user     - when detaching, run as specified user\n"
					"       -g run-as-group    - when detaching, run as specified group\n"
					"       -f syslog-facility - use specified facility for syslogs (default 'user')\n"
       				"       -d                 - detach from calling process (daemonize)\n"
                    "       -p                 - read packets from interface in promiscous mode\n\n");
}

Args *getArgs(int argc, char **argv)
{
	Args *a = malloc(sizeof(Args));
	if(a == NULL)
		return NULL;
	memset(a, 0, sizeof(Args));

	a->maxsessions = 8192;
	a->maxhosts    = 1024;
	a->promisc     = 1;
	a->scenarioDir = icsStrdup(DEFAULT_SCENARIO_DIR);

	int last = 0;
	for(int i=1; i < argc; i++) {
		if(strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
			usage();
		else
		if(strcmp(argv[i], "-f") == 0)
			a->facility = icsStrdup(argv[++i]);
		else
		if(strcmp(argv[i], "-S") == 0)
			a->scenarioDir = icsStrdup(argv[++i]);
		else
		if(strcmp(argv[i], "-r") == 0)
			a->inputfile = icsStrdup(argv[++i]);
		else
		if(strcmp(argv[i], "-i") == 0)
			a->interface = icsStrdup(argv[++i]);
		else
		if(strcmp(argv[i], "-l") == 0)
			a->pinnedlist = icsStrdup(argv[++i]);
		else
		if(strcmp(argv[i], "-p") == 0)
			a->promisc = atoi(argv[++i]);
		else
		if(strcmp(argv[i], "-s") == 0)
			a->maxsessions = atoi(argv[++i]);
		else
		if(strcmp(argv[i], "-H") == 0)
			a->maxhosts = atoi(argv[++i]);
		else
		if(strcmp(argv[i], "-u") == 0)
			a->user = icsStrdup(argv[++i]);
		else
		if(strcmp(argv[i], "-g") == 0)
			a->group = icsStrdup(argv[++i]);
		else
		if(strcmp(argv[i], "-R") == 0)
			a->chroot = icsStrdup(argv[++i]);
		else
		if(strcmp(argv[i], "-d") == 0)
			a->detach = 1;
		else 
		if(strcmp(argv[i], "-D") == 0)
			a->debug = 1;
		else 
		if(argv[i][0] == '-')
			usage();
		else {
			last = i;
			break;
		}
	}

	if(a->detach) {
		a->debug = 0;
		ICS_FREE(a->inputfile);
	}

	if(a->inputfile == NULL && a->interface == NULL)
		a->interface = icsStrdup("any");

	if(last == 0)
		return a;

	int l = 0;
	for(int i=last; i < argc; i++)
		l += strlen(argv[i]);
	a->filter = malloc(l + (argc - last) + 1);
	strcpy(a->filter, "");
	if(a->filter != NULL) {
		for(int i=last; i < argc; i++) {
			if(i != last)
				strcat(a->filter, " ");
			strcat(a->filter, argv[i]);
		}
	}

	return a;
}

void freeArgs(Args *args)
{
	if(args != NULL) {
		if(args->chroot != NULL)
			ICS_FREE(args->chroot);
		if(args->scenarioDir != NULL)
			ICS_FREE(args->scenarioDir);
		if(args->inputfile != NULL)
			ICS_FREE(args->inputfile);
		if(args->interface != NULL)
			ICS_FREE(args->interface);
		if(args->filter != NULL)
			ICS_FREE(args->filter);
		if(args->pinnedlist != NULL)
			ICS_FREE(args->pinnedlist);
		if(args->group != NULL)
			ICS_FREE(args->group);
		if(args->user != NULL)
			ICS_FREE(args->user);
		if(args->facility != NULL)
			ICS_FREE(args->facility);
		ICS_FREE(args);
	}
}

