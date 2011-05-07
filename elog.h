#ifndef elog_h
#define elog_h

/*
 * TODO:
 * - Remove doxygen comments, add comments according to coding style
 * - Remove remaining camel-back naming (mainly in elog.c)
 */

/** @file elog.h
 * @brief Logging utilities
 */

#include <stdarg.h>
#include <syslog.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Set the maximum log file limit to 2 mb */
#define MAX_LOGSIZE (2*1000*1024)

/**
 * @defgroup VipLog Logging utilities used by VIP
 * This logging interface can be a front-end for the "real"
 * logging servce that will eventually be used.
 */
/*@{*/

/**
 * Defines the logging output channel
 */
enum Elogchannel {
    ELOG_STDERR,		/**< Log to stderr  */
    ELOG_SYSLOG,		/**< Log to the syslog  */
    ELOG_FILE,			/**< Log to a specified file */
    ELOG_AIS			/**< Use the AIS logging service */
};


/**
 * The logging output device.
 */
typedef struct Elogoutput {
    enum Elogchannel channel;
    union {
	char const* filename;
        int facility;
    } channel_param;
} Elogoutput;

void elog_setlevel(int level);

/**
 * Get log level
 */
unsigned int elog_getlevel(void);

/**
 * Utility function to convert an integer 0..7 to LOG_LOCAL0 through LOG_LOCAL7
 */
int convert_to_facility(int);

/**
 * Initiate VIP logging.
 * @param elogId Id used for logging. The pointer will be stored, so it
 *	must not point to strin on the stack for instance.
 * @param output Log output channel, if NULL is specified 'stderr' is used.
 */
void elog_init(const char* elog_id, Elogoutput* output);

/**
 * Set the Log output channel
 */
void elog_output(Elogoutput* output);

/** Log a message vararg version */
void velog(int priority, char const* fmt, va_list ap);

/** Log a message */
void elog(int priority,
	  char const* fmt, ...) __attribute__ ((format (printf,2,3)));

/**
 * Log a message and exit the program with an error code.
 * If 'errno' is not zero errno will be logged also (as text).
 */
void errquit(char const* fmt, ...) __attribute__ ((format (printf,1,2)));

/*@}*/

#define max(a,b) (((a)>(b))?(a):(b))

/* debugging macros so we can pin down message provenance at a glance */
#ifndef DEBUG
#define INFO(...) elog(LOG_INFO,    __VA_ARGS__)
#define ERR(...)  elog(LOG_ERR,     __VA_ARGS__)
#define WARN(...) elog(LOG_WARNING, __VA_ARGS__)
#endif
#define ERR_EXIT(...) do { \
   elog(LOG_ERR, __VA_ARGS__); \
   exit(-1); \
} while(0)


#ifdef DEBUG
#include <stdio.h>
#include <stdarg.h>
#define D(...)    d_wrapper(LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define INFO(...) d_wrapper(LOG_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define ERR(...)  d_wrapper(LOG_ERR, __FILE__, __LINE__, __VA_ARGS__)
#define WARN(...) d_wrapper(LOG_WARNING, __FILE__, __LINE__, __VA_ARGS__)
void d_wrapper(int prio, const char *file, const int line, const char *fmt, ...);
#define theformat "[%-13.13s:%4d: %-20.20s] "
#else
#define D(...)
#endif

#ifdef __cplusplus
}
#endif
#endif
