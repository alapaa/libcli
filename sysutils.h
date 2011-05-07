#ifndef _SYSUTILS_H_
#define _SYSUTILS_H_

#include <sys/socket.h>
#include <sys/time.h>

/* This is to avoid container crashes */
#define MODPROBE_FIX

#define MAX_NAMELEN 64
#define MAX_CMDLEN 128
#define MAX_DEVICE_NAME 16

void get_alb_tunnel_name(char *name, int max_size, const char *alb_name);
char* safe_strncpy(char *dest, const char *src, size_t n);

int safe_snprintf(char *string, ssize_t maxlen, const char *format, ...);

int run_cmd(char *cmd, char ***linebuf_ptr, unsigned int *linecnt_ptr);
int run_cmd2(char* command);
void run_cmd_release_buf(char **linebuf,unsigned int lines);
void run_cmd_printout(const char *cmd,unsigned int max_printout);
int daemonize(char *cmd, char **args);
int timeval_subtract(struct timeval *result, struct timeval *stop, struct timeval *start);

#ifdef DEBUG
void print_trace(void);
#endif


#endif
