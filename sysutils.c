#include <sys/wait.h>
#include "elog.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#ifdef DEBUG
#include <execinfo.h>
#endif

#include "sysutils.h"
#include "iputils.h"

void remove_newline(char* str)
{
    while (*str) {
        if (*str=='\n' || *str=='\r') {
            *str=' ';
        }
        str++;
    }
}

int run_cmd(char *cmd, char ***linebuf_ptr, unsigned int *linecnt_ptr)
{
    FILE *outdata;
    int  maxlines=20000;
    char buf[256]={0};
    int  line=0;

    (*linebuf_ptr)=(char **)malloc(maxlines*sizeof(char *));

    if (!(outdata=popen(cmd, "r"))) {
        perror("pipe");
        return -1;
    }

    while (!feof(outdata)) {
        if (fgets(buf,256,outdata)) {
            (*linebuf_ptr)[line]=strdup(buf);
            remove_newline((*linebuf_ptr)[line]);
            line++;
            if (line>=maxlines) {
                (*linecnt_ptr)=line;
                pclose(outdata);
                return line;
            }
        }
    }

    (*linecnt_ptr)=line;
    pclose(outdata);
    return line;
}

int run_cmd2(char* command)
{
    int ret=0;
    pid_t pid;
    INFO("Running command: %s",command);
    pid=fork();
    if (pid<0) {
        ERR("FAILED, Command: %s",command);
        return -1;
    } else if (pid>0) {
        waitpid(pid,&ret,0);
    } else {
        char *argv[128], *tok, *p, *start = strdup(command);
        int argc=0;
        while( (tok=strtok_r(start, " \t", &p)) && argc<127) {
            start=NULL;
            argv[argc++]=tok;
        }
        argv[argc]=0;
        execvp(argv[0],argv);
        exit(-1);
    }

    if ( (WIFEXITED(ret)==0 || WEXITSTATUS(ret) != 0) ) {
        ERR("FAILED %d, Command: '%s'\nerrno: '%s'", WEXITSTATUS(ret), command,
            strerror(errno));
    }
    return WEXITSTATUS(ret);
}

void run_cmd_release_buf(char **linebuf, unsigned int lines)
{
    int i;
    for(i=0;i<lines;i++) {
        free(linebuf[i]);
    }
    free(linebuf);
}

void run_cmd_printout(const char *cmd,unsigned int max_printout) {

    char **linebuf;
    unsigned int linecount;
    char buf[max_printout];
    int i,rc;

    snprintf(buf, max_printout,"%s",cmd);
    rc = run_cmd(buf, &linebuf, &linecount);
    if (rc < 0) {
        ERR("error in run_cmd used in %s",__FUNCTION__);
        return;
    }
    for (i=0;i<linecount;i++) {
        D("%s",linebuf[i]);
    }
    run_cmd_release_buf(linebuf,linecount);
}

char* safe_strncpy(char *dest, const char *src, size_t n)
{
    char *p;
    p = strncpy(dest, src, n);
    dest[n-1]=0;
    return p;
}

int safe_snprintf(char *string, ssize_t maxlen, const char *format, ...)
{
    int ret;
    va_list args;

    if (maxlen < 0 || maxlen > 20000) {
        maxlen = 0;
    }

    va_start(args, format);
    ret = vsnprintf(string, maxlen, format, args);
    va_end(args);
    return ret;
}

int daemonize(char *cmd, char **args)
{
    int fd0, fd1, fd2;
    pid_t pid;
    struct rlimit r1;
    struct sigaction sa;

    /* Clear file creation */
    umask(0);

    /* Get max fd:s */
    if (getrlimit(RLIMIT_NOFILE, &r1) < 0) {
        ERR("%s: Can't get file limit", cmd);
        return 1;
    }

#ifdef DEBUG
    /* Print cmd and args */
    {
        char buf[256];
        char **ptr = args;
        int count = 0;
        count += safe_snprintf(buf+count, sizeof(buf)-count, "cmd: ");
        while (*ptr) {
            count += safe_snprintf(buf+count, sizeof(buf)-count, "%s ", *ptr);
            ptr++;
        }
        D("%s", buf);
    }
#endif

    /* Become session leader */
    if ( (pid=fork()) < 0) {
        ERR("%s Can't fork", cmd);
        return 1;
    } else if (pid != 0) {
        /* parent */
        return 0;
    }

    /* child */
    setsid();

    /* Ensure future opens won't allocate controlling TTYs */
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGHUP, &sa, NULL) < 0 ) {
        ERR_EXIT("%s: Can't ignore SIGHUP", cmd);
    }

    if ( (pid=fork()) < 0) {
        ERR_EXIT("%s Can't fork", cmd);
    } else if (pid != 0) {
        /* parent */
        exit(0);
    }

    /* child */

    /* Change pwd to prevent file system to be unmounted */
    if (chdir("/") < 0) {
        ERR_EXIT("%s: Can't change directory to /", cmd);
    }

    /* Close all open fds */
    if (r1.rlim_max == RLIM_INFINITY) {
        r1.rlim_max = 1024;
    }

    {
        int i;
        for(i=0; i<r1.rlim_max; i++)  {
            close(i);
        }
    }

    /* Attach fds 0,1,2 to /dev/null */
    fd0 = open("/dev/null", O_RDWR);
    fd1 = dup(0);
    fd2 = dup(0);


    /* Initialize log file */
    if (fd0 != 0 || fd1 != 1 || fd2 != 2) {
        syslog(LOG_ERR, "unexpected file descriptors %d %d %d", fd0, fd1, fd2);
        ERR_EXIT("unexpected file descriptors %d %d %d", fd0, fd1, fd2);
    }

    if (execvp(cmd, args) == -1) {
        ERR_EXIT("execvp returned with error.");
    }

    /* If this line is reached something is very wrong. */
    ERR_EXIT("execvp returned with error.");
}

/*
  gettimeofday(&start, NULL);
  ... do stuff ...
  gettimeofday(&start, NULL);
  timeval_subtract(&result, &stop, &start);
 */
int timeval_subtract(struct timeval *result, struct timeval *stop, struct timeval *start)
{
    if (stop->tv_usec < start->tv_usec) {
        int nsec = (start->tv_usec - stop->tv_usec) / 1000000 + 1;
        start->tv_usec -= 1000000 * nsec;
        start->tv_sec += nsec;
    }
    if (stop->tv_usec - start->tv_usec > 1000000) {
        int nsec = (start->tv_usec - stop->tv_usec) / 1000000;
        start->tv_usec += 1000000 * nsec;
        start->tv_sec -= nsec;
    }

    result->tv_sec = stop->tv_sec - start->tv_sec;
    result->tv_usec = stop->tv_usec - start->tv_usec;

    return stop->tv_sec < start->tv_sec;
}

#ifdef DEBUG
void print_trace(void)
{
    void *array[30];
    size_t size;
    char **strings;
    size_t i;

    size = backtrace(array, 30);
    strings = backtrace_symbols(array, size);

    D("Obtained %zd stack frames.", size);

    for (i = 0; i < size; i++)
        D("    %s", strings[i]);

    free(strings);
}

#endif
