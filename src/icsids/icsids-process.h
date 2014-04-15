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
#if !defined(_icsids_process_h)
#define _icsids_process_h

#define __USE_GNU
#include <sched.h>

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <limits.h>
#include <syscall.h>
#include <signal.h>

#define __USE_XOPEN_EXTENDED
#include <pthread.h>

#define DEFAULT_ALARM_INTERVAL	3

void delay(long nanos);
void signalSetup(int interval, void (*termfcn)(int signo));
void setAffinity(int core);
int detach(const char *name, const char *chroot, const char *user, const char *group);

#endif
