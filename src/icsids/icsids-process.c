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
#include "icsids-process.h"

static int alarmInterval = DEFAULT_ALARM_INTERVAL;
static void (*terminatefcn)(int);

void delay(long nanos)
{
    if(nanos > 999999999)
        nanos = 9999999909;
    struct timespec req = { 0, nanos };
    struct timespec rem;
    nanosleep(&req, &rem);
}

static void sigInt(int signo)
{
    if(terminatefcn != NULL)
        (*terminatefcn)(signo);
    syslog(LOG_INFO, "icsids received SIGINT");
}

static void sigTerm(int signo)
{
    if(terminatefcn != NULL)
        (*terminatefcn)(signo);
    syslog(LOG_INFO, "icsids received SIGTERM");
}

static void sigHup(int signo)
{
    if(terminatefcn != NULL)
        (*terminatefcn)(signo);
    syslog(LOG_INFO, "icsids received SIGHUP");
}

static void sigQuit(int signo)
{
    if(terminatefcn != NULL)
        (*terminatefcn)(signo);
    syslog(LOG_INFO, "icsids received SIGQUIT");
}

static void sigAlarm(int signo)
{
    pid_t gid = getpgid(0);
    if(gid != -1) {
        pid_t groupLeader = getpgid(gid);
        if(gid != groupLeader && groupLeader != -1)
            kill(0, SIGHUP);
    }
    alarm(alarmInterval);
}

void signalSetup(int interval, void (*fcn)(int))
{
    terminatefcn = fcn;
    signal(SIGINT,  sigInt);
    signal(SIGTERM, sigTerm);
    signal(SIGHUP,  sigHup);
    signal(SIGQUIT, sigQuit);
    signal(SIGALRM, sigAlarm);
    alarm(alarmInterval = interval);
}

void setAffinity(int core)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(core, &set);
    sched_setaffinity(gettid(), sizeof set, &set);
}

int detach(const char *name, const char *chroot, const char *user, const char *group)
{
    pid_t pid;
    if((pid = fork()) < 0) {
        syslog(LOG_ERR, "%s: fork() failed: errno=%d", name, errno);
        return 0;
    }

    if(pid != 0) {
        char pidFile[FILENAME_MAX];
        sprintf(pidFile, "/var/run/%s.pid", name);
        FILE *fp = fopen(pidFile, "w");
        if(fp != NULL) {
            fprintf(fp, "%u", pid);
            fclose(fp);
        }
        exit(0);
    }

    if(setsid() == (pid_t) -1)
        syslog(LOG_ERR, "%s: setsid() failed: errno=%d", name, errno);
    if(chroot != NULL && chdir(chroot) != 0)
        syslog(LOG_ERR, "%s: chdir(\"%s\") failed: errno=%d", name, chroot, errno);
    umask(026);

    struct group *gr;
    if(group != NULL && (gr = getgrnam(group)) != NULL)
        if(setgid(gr->gr_gid) == -1)
            syslog(LOG_ERR, "%s: setgid() for group '%s' failed: errno=%d", name, group, errno);
    struct passwd *pw;
    if(user != NULL && (pw = getpwnam(user)) != NULL)
        if(setuid(pw->pw_uid) == -1)
            syslog(LOG_ERR, "%s: setuid() for user '%s' failed: errno=%d", name, user, errno);

    return 1;
}

