#ifndef __LIBCLI_H__
#define __LIBCLI_H__

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Erik Alapää, 2011
 *
 * Code derived from libcli (LGPL) by David Parrish david@dparrish.com.
 * Original code heavily modified to support single-threading and libev,
 * i.e. removed fork() and select(). Added coroutine support from Simon Tatham
 * for facilitating this major re-write.
 */

// TODO: Check if enabling callback when libev finds socket writable needs
//       re-thinking.

#include <stdio.h>
#include <stdarg.h>

#include <ev.h>

#include "coroutine.h"

#define CLI_OK			0
#define CLI_ERROR		-1
#define CLI_QUIT		-2
#define CLI_ERROR_ARG		-3
#define CLI_UNINITIALIZED       -4
#define MAX_HISTORY		256


#define PRIVILEGE_UNPRIVILEGED	0
#define PRIVILEGE_PRIVILEGED	15
#define MODE_ANY		-1
#define MODE_EXEC		0
#define MODE_CONFIG		1

#define LIBCLI_HAS_ENABLE	1

#define PRINT_PLAIN		0
#define PRINT_FILTERED		0x01
#define PRINT_BUFFERED		0x02

#define CLI_MAX_LINE_LENGTH     4096
#define CLI_MAX_LINE_WORDS      128

// Event type. These should be identical to libev, and should be easy to use
// with other descriptor handlers such as select, poll, epoll etc.

#define CLI_EVENT_READ           0x01 /* descriptor read will not block */
#define CLI_EVENT_WRITE          0x02 /* descriptor write will not block */

struct cli_def {
    int completion_callback;
    struct cli_command *commands;
    int (*auth_callback)(char *, char *);
    int (*regular_callback)(struct cli_def *cli);
    int (*enable_callback)(char *);
    char *banner;
    struct unp *users;
    char *enable_password;
    char *history[MAX_HISTORY];
    char showprompt;
    char *promptchar;
    char *hostname;
    char *modestring;
    int privilege;
    int mode;
    int state;
    struct cli_filter *filters;
    void (*print_callback)(struct cli_def *cli, char *string);
    FILE *client;
    /* internal buffers */
    void *conn;
    void *service;
    char *commandname;  // temporary buffer for cli_command_name() to prevent
                        // leak
    char *buffer;
    unsigned buf_size;
    struct timeval timeout_tm;
    unsigned int idle_timeout;
    int (*idle_timeout_callback)(struct cli_def *);
    time_t last_action;

    ccrContext z; // Re-entrant state for using coroutine lib from Simon Tatham
    int fd; // Descriptor for this client
    int revents;
    int callback_only_on_fd_readable;
    int wanted_revents;
    void *udata; // Generic user data
};

struct cli_filter {
    int (*filter)(struct cli_def *cli, char *string, void *data);
    void *data;
    struct cli_filter *next;
};

struct cli_command {
    char *command;
    int (*callback)(struct cli_def *, char *, char **, int);
    unsigned int unique_len;
    char *help;
    int privilege;
    int mode;
    struct cli_command *next;
    struct cli_command *children;
    struct cli_command *parent;
};


/*
 *  This must be called before any other cli_yyy function.  It sets up the
 *  internal data structures used for command-line processing.
 *
 *  Returns a struct cli_def * which must be passed to all other cli_yyy
 *   functions.
 */
struct cli_def *cli2_init();

/*
 * This frees memory used by libcli.
 */
int cli_done(struct cli_def *cli);

/*
 * Add a command to the internal command tree.  Returns a struct cli_command *,
 * which you can pass as parent to another call to cli_register_command().
 *
 * When the command has been entered by the user, callback
 * is checked. If it is not NULL, then the callback is called with:
 * 	struct cli_def *   the handle of the cli structure.  This
 * 	                   must be passed to all cli functions, including
 * 	                   cli_print().
 * 	char *             the entire command which was entered. This is after
 *                         command expansion.
 * 	char **            the list of arguments entered
 * 	int                the number of arguments entered
 *
 * The callback must return CLI_OK if the command was successful, CLI_ERROR if
 * processing wasn't successful and the next matching command should be tried
 * (if any), or CLI_QUIT to drop the connection (e.g. on a fatal error).
 *
 * If parent is NULL, the command is added to the top level of commands,
 * otherwise it is a subcommand of parent.
 *
 * privilege should be set to either PRIVILEGE_PRIVILEGED or
 * PRIVILEGE_UNPRIVILEGED.  If set to PRIVILEGE_PRIVILEGED then the user must
 * have entered enable before running this command.
 *
 * mode should be set to MODE_EXEC for no configuration mode, MODE_CONFIG for
 * generic configuration commands, or your own config level.  The user can
 * enter the generic configuration level by entering configure terminal, and
 * can return to MODE_EXEC by entering exit or CTRL-Z.  You can define commands
 * to enter your own configuration levels, which should call the
 * cli_set_configmode() function.
 *
 * If help is provided, it is given to the user when he/she enters the help
 * command or presses ?.
 */
struct cli_command *cli_register_command(
    struct cli_def *cli,
    struct cli_command *parent,
    char *command,
    int (*callback)(struct cli_def *, char *, char **, int),
    int privilege,
    int mode,
    char *help);

/*
 * Remove a command and all children.  There is not provision yet for removing
 * commands at lower than the top level.
 */
int cli_unregister_command(struct cli_def *cli, char *command);

int cli_run_command(struct cli_def *cli, char *command);

int cli_process_event(struct cli_def *cli);

/*
 * This reads and processes every line read from f as if it were entered at the
 * console.  The privilege level will be set to privilege and mode set to mode
 * during the processing of the file.
 */
int cli_file(struct cli_def *cli, FILE *fh, int privilege, int mode);

/*
 * Enables or disables callback based authentication.  If auth_callback is not
 * NULL, then authentication will be required on connection.  auth_callback
 * will be called with the username and password that the user enters.
 *
 * auth_callback must return a non-zero value if authentication is successful.
 *
 * If auth_callback is NULL, then callback based authentication will be
 * disabled.
 */
void cli_set_auth_callback(struct cli_def *cli,
                           int (*auth_callback)(char *, char *));

/*
 * Just like cli_set_auth_callback this takes a pointer to a callback function
 * to authorize privileged access.  However this callback only takes a single
 * string - the password.
 */
void cli_set_enable_callback(struct cli_def *cli,
                             int (*enable_callback)(char *));

/*
 * Enables internal authentication, and adds username/password to the list of
 * allowed users.
 *
 * The internal list of users will be checked before callback based
 * authentication is tried.
 */
void cli_allow_user(struct cli_def *cli, char *username, char *password);

/*
 * This will allow a static password to be used for the enable command.  This
 * static password will be checked before running any enable callbacks.
 *
 * Set this to NULL to not have a static enable password.
 */
void cli_allow_enable(struct cli_def *cli, char *password);

/*
 * Removes username/password from the list of allowed users.
 *
 * If this is the last combination in the list, then internal authentication
 * will be disabled.
 */
void cli_deny_user(struct cli_def *cli, char *username);

/*
 * Sets the greeting that clients will be presented with when they connect.
 * This may be a security warning for example.
 *
 * If this function is not called or called with a NULL argument, no banner
 * will be presented.
 */
void cli_set_banner(struct cli_def *cli, char *banner);

/*
 * Sets the hostname to be displayed as the first part of the prompt.
 */
void cli_set_hostname(struct cli_def *cli, char *hostname);

void cli_set_promptchar(struct cli_def *cli, char *promptchar);
void cli_set_modestring(struct cli_def *cli, char *modestring);
int cli_set_privilege(struct cli_def *cli, int privilege);

/*
 * This will set the configuration mode. Once set, commands will be restricted
 * to only ones in the selected configuration mode, plus any set to MODE_ANY.
 * The previous mode value is returned.
 *
 * The string passed will be used to build the prompt in the set configuration
 * mode.  e.g. if you set the string test, the prompt will become:
 * hostname(config-test)#
 *
 */
int cli_set_configmode(struct cli_def *cli, int mode, char *config_desc);

void cli_reprompt(struct cli_def *cli);

/*
 * Adds a callback function which will be called every second that a user is
 * connected to the cli.  This can be used for regular processing such as
 * debugging, time counting or implementing idle timeouts.
 *
 * Pass NULL as the callback function to disable this at runtime.  If the
 * callback function does not return CLI_OK, then the user will be
 * disconnected.
 */
void cli_regular(struct cli_def *cli, int (*callback)(struct cli_def *cli));

void cli_regular_interval(struct cli_def *cli, int seconds);

/*
 * This function should be called for any output generated by a command
 * callback.
 *
 * It takes a printf() style format string and a variable number of arguments.
 *
 * Be aware that any output generated by cli_print will be passed through any
 * filter currently being applied, and the output will be redirected to the
 * cli_print_callback() if one has been specified.
 */
void cli_print(struct cli_def *cli, char *format, ...)
    __attribute__((format (printf, 2, 3)));
void cli_bufprint(struct cli_def *cli, char *format, ...)
    __attribute__((format (printf, 2, 3)));
void cli_vabufprint(struct cli_def *cli, char *format, va_list ap);

/*
 * A variant of cli_print() which does not have filters applied.
 */
void cli_error(struct cli_def *cli, char *format, ...)
    __attribute__((format (printf, 2, 3)));

/*
 * Whenever cli_error() is called, the output generally goes to the user.  If
 * you specify a callback using this function, then the output will be sent to
 * that callback.  The function will be called once for each line, and it will
 * be passed a single null-terminated string, without any newline characters.
 *
 * Specifying NULL as the callback parameter will make libcli use the
 * default cli_print() function.
 */
void cli_print_callback(struct cli_def *cli,
                        void (*callback)(struct cli_def *, char *));

void cli_free_history(struct cli_def *cli);
void cli_set_idle_timeout(struct cli_def *cli, unsigned int seconds);
void cli_set_idle_timeout_callback(struct cli_def *cli, unsigned int seconds,
                                   int (*callback)(struct cli_def *));

#ifdef __cplusplus
}
#endif

#endif
