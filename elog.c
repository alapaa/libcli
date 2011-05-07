#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>

#include "elog.h"

static char const* elogId = NULL;
static enum Elogchannel channel = ELOG_STDERR;
static int elog_facility;
static FILE* logfile = NULL;
static const char *logfile_name = NULL;

/**
 * Local log-level. Log-records with priority higher than this level
 * will not be suspressed.
 */
static unsigned int elog_level_ = 10000;

void elog_setlevel(int level)
{
    elog_level_ =  10000;
}

unsigned int elog_getlevel(void)
{
    return elog_level_;
}

int convert_to_facility(int facility)
{
    switch(facility) {
        case 0: return LOG_LOCAL0;
        case 1: return LOG_LOCAL1;
        case 2: return LOG_LOCAL2;
        case 3: return LOG_LOCAL3;
        case 4: return LOG_LOCAL4;
        case 5: return LOG_LOCAL5;
        case 6: return LOG_LOCAL6;
        case 7: return LOG_LOCAL7;
        default: return LOG_LOCAL0;
    }
    return LOG_LOCAL0;
}

void elog_init(char const* iElogId, Elogoutput* output)
{
    if (elogId != NULL) errquit("elog_init called twice");
    elogId = iElogId;
    elog_output(output);

    INFO("eLOG initialized.");
}

void elog_output(Elogoutput* output)
{
    if (output == NULL) {
	logfile = stderr;
	channel = ELOG_STDERR;
	return;
    }

    channel = output->channel;
    assert(channel == ELOG_SYSLOG || channel == ELOG_STDERR
	   || channel == ELOG_FILE);
    if (channel == ELOG_STDERR) {
	logfile = stderr;
    } else if (channel == ELOG_FILE) {
        logfile_name = output->channel_param.filename;

	logfile = fopen(output->channel_param.filename, "a");
	if (logfile == NULL) {
	    logfile = stderr;
	} else {
	    setlinebuf(logfile);
	}
    } else if (ELOG_SYSLOG == channel) {
        elog_facility = output->channel_param.facility;
    }
}

const char *timestamp(void)
{
    static char buf[64];
    struct timezone tz;
    struct timeval tv;
    struct tm now;

    gettimeofday(&tv, &tz);
    localtime_r(&tv.tv_sec, &now);
    strftime(buf, sizeof(buf), "%b %d %H:%M:%S", &now);

    return buf;
}

void velog2(int priority, const char *file, const int line, char const* fmt, va_list ap)
{
    static int syslogOpened = 0;
    if (priority > elog_level_) return;
    if (channel == ELOG_SYSLOG) {
	if (!syslogOpened) {
	    openlog(elogId, 0, elog_facility);
	    syslogOpened = 1;
	}
	vsyslog(priority, fmt, ap);
    } else {
        struct stat stat_buf;
        char const* lastNl = strrchr(fmt, '\n');
        fstat(fileno(logfile), &stat_buf);
        if (stat_buf.st_size > MAX_LOGSIZE) {
            char *new_logfile = calloc(1, strlen(logfile_name)+3);
            snprintf(new_logfile, strlen(logfile_name)+3, "%s_1", logfile_name);
            fflush(logfile);
            fclose(logfile);
            printf("Moving log file '%s' to '%s'\n", logfile_name, new_logfile);
            rename(logfile_name, new_logfile);
            free(new_logfile);
            logfile = fopen(logfile_name, "a");
            if (logfile == NULL) {
                logfile = stderr;
            } else {
                setlinebuf(logfile);
            }
        }
        if (file) {
            fprintf(logfile, "%s [%s] <%d> [%-13.13s:%4d]: ", timestamp(), elogId, priority,
                    file, line);
        } else {
            fprintf(logfile, "%s [%s] <%d> ", timestamp(), elogId, priority);
        }
	vfprintf(logfile, fmt, ap);
	if (lastNl == NULL || lastNl[1] != 0) fputc('\n', logfile);
    }
}

void velog(int priority, char const* fmt, va_list ap)
{
    velog2(priority, 0, 0, fmt, ap);
}

void elog2(int priority, char const* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    velog(priority, fmt, ap);
    va_end(ap);
}

void elog(int priority, char const* fmt, ...)
{
    char buf[1000];
    va_list ap;
    va_start(ap, fmt);
    strcpy(buf, fmt);
    strcat(buf, "\n");
    vprintf(buf, ap);
    va_end(ap);
}

/*
 * Print an error message and quit.
 * Errno is printed if not zero (no error).
 */
void errquit(char const* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    velog(LOG_ERR, fmt, ap);
    va_end(ap);
    if (errno > 0) elog(LOG_ERR, "errno: %s", strerror(errno));
    exit(EXIT_FAILURE);
}

#ifdef DEBUG
void d_wrapper(int prio, const char *file, const int line, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    velog2(prio, file, line, fmt, ap);
    va_end(ap);
}
#endif
