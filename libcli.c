#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <memory.h>
#if !defined(__APPLE__) && !defined(__FreeBSD__)
#include <malloc.h>
#endif
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>

#include <assert.h>

#ifndef WIN32
#include <regex.h>
#endif

#include "elog.h"
#include "libcli.h"

#ifdef CLI_NB_ST
#include "coroutine.h"

#endif

#define CCR_VAR_LIST     unsigned char c;       \
    int n; \
    int l; \
    int oldl; \
    int is_telnet_option; \
    int skip; \
    int esc; \
    int cursor; \
    int insertmode; \
    char *cmd; \
    char *oldcmd; \
    char *username; \
    char *password; \
    char *negotiate; \
    ssize_t nwritten; \
    ssize_t nwanted; \
    signed int in_history; \
    int lastchar; \

// vim:sw=4 ts=8

#ifdef __GNUC__
# define UNUSED(d) d __attribute__ ((unused))
#else
# define UNUSED(d) d
#endif

#ifdef WIN32
/*
 * Stupid windows has multiple namespaces for filedescriptors, with different
 * read/write functions required for each ..
 */
int read(int fd, void *buf, unsigned int count) {
    return recv(fd, buf, count, 0);
}

int write(int fd,const void *buf, unsigned int count) {
    return send(fd, buf, count, 0);
}

int vasprintf(char **strp, const char *fmt, va_list args) {
    int size;

    size = vsnprintf(NULL, 0, fmt, args);
    if ((*strp = malloc(size + 1)) == NULL) {
        return -1;
    }

    size = vsnprintf(*strp, size + 1, fmt, args);
    return size;
}

int asprintf(char **strp, const char *fmt, ...) {
    va_list args;
    int size;

    va_start(args, fmt);
    size = vasprintf(strp, fmt, args);

    va_end(args);
    return size;
}

int fprintf(FILE *stream, const char *fmt, ...) {
    va_list args;
    int size;
    char *buf;

    va_start(args, fmt);
    size = vasprintf(&buf, fmt, args);
    if (size < 0) {
        goto out;
    }
    size = write(stream->_file, buf, size);
    free(buf);

out:
    va_end(args);
    return size;
}

/*
 * Dummy definitions to allow compilation on Windows
 */
int regex_dummy() {return 0;};
#define regfree(...) regex_dummy()
#define regexec(...) regex_dummy()
#define regcomp(...) regex_dummy()
#define regex_t int
#define REG_NOSUB	0
#define REG_EXTENDED	0
#define REG_ICASE	0
#endif

const char *cli_rc_to_str(int rc)
{
    switch(rc) {
    case CLI_OK:
        return "CLI_OK";
    case CLI_ERROR:
        return "CLI_ERROR";
    case CLI_QUIT:
        return "CLI_QUIT";
    case CLI_ERROR_ARG:
        return "CLI_ERROR_ARG";
    case CLI_UNINITIALIZED:
        return "CLI_UNINITIALIZED";
    default:
        return "Unknown error code";
    }
}

enum cli_states {
    STATE_LOGIN,
    STATE_PASSWORD,
    STATE_NORMAL,
    STATE_ENABLE_PASSWORD,
    STATE_ENABLE
};

struct unp {
    char *username;
    char *password;
    struct unp *next;
};

struct cli_filter_cmds
{
    char *cmd;
    char *help;
};

/* free and zero (to avoid double-free) */
#define free_z(p) do { if (p) { free(p); (p) = 0; } } while (0)

int cli_match_filter_init(struct cli_def *cli, int argc, char **argv, struct cli_filter *filt);
int cli_range_filter_init(struct cli_def *cli, int argc, char **argv, struct cli_filter *filt);
int cli_count_filter_init(struct cli_def *cli, int argc, char **argv, struct cli_filter *filt);
int cli_match_filter(struct cli_def *cli, char *string, void *data);
int cli_range_filter(struct cli_def *cli, char *string, void *data);
int cli_count_filter(struct cli_def *cli, char *string, void *data);

static struct cli_filter_cmds filter_cmds[] =
{
    { "begin",   "Begin with lines that match" },
    { "between", "Between lines that match" },
    { "count",   "Count of lines"   },
    { "exclude", "Exclude lines that match" },
    { "include", "Include lines that match" },
    { "grep",    "Include lines that match regex (options: -v, -i, -e)" },
    { "egrep",   "Include lines that match extended regex" },
    { NULL, NULL}
};

char *cli_command_name(struct cli_def *cli, struct cli_command *command)
{
    char *name = cli->commandname;
    char *o;

    if (name) free(name);
    if (!(name = calloc(1, 1)))
        return NULL;

    while (command)
    {
        o = name;
        asprintf(&name, "%s%s%s", command->command, *o ? " " : "", o);
        command = command->parent;
        free(o);
    }
    cli->commandname = name;
    return name;
}

void cli_set_auth_callback(struct cli_def *cli, int (*auth_callback)(char *, char *))
{
    cli->auth_callback = auth_callback;
}

void cli_set_enable_callback(struct cli_def *cli, int (*enable_callback)(char *))
{
    cli->enable_callback = enable_callback;
}

void cli_allow_user(struct cli_def *cli, char *username, char *password)
{
    struct unp *u, *n;
    if (!(n = malloc(sizeof(struct unp))))
    {
        fprintf(stderr, "Couldn't allocate memory for user: %s", strerror(errno));
        return;
    }
    if (!(n->username = strdup(username)))
    {
        fprintf(stderr, "Couldn't allocate memory for username: %s", strerror(errno));
        free(n);
        return;
    }
    if (!(n->password = strdup(password)))
    {
        fprintf(stderr, "Couldn't allocate memory for password: %s", strerror(errno));
        free(n->username);
        free(n);
        return;
    }
    n->next = NULL;

    if (!cli->users)
        cli->users = n;
    else
    {
        for (u = cli->users; u && u->next; u = u->next);
        if (u) u->next = n;
    }
}

void cli_allow_enable(struct cli_def *cli, char *password)
{
    free_z(cli->enable_password);
    if (!(cli->enable_password = strdup(password)))
    {
        fprintf(stderr, "Couldn't allocate memory for enable password: %s", strerror(errno));
    }
}

void cli_deny_user(struct cli_def *cli, char *username)
{
    struct unp *u, *p = NULL;
    if (!cli->users) return;
    for (u = cli->users; u; u = u->next)
    {
        if (strcmp(username, u->username) == 0)
        {
            if (p)
                p->next = u->next;
            else
                cli->users = u->next;
            free(u->username);
            free(u->password);
            free(u);
            break;
        }
        p = u;
    }
}

void cli_set_banner(struct cli_def *cli, const char *banner)
{
    free_z(cli->banner);
    if (banner && *banner)
        cli->banner = strdup(banner);
}

void cli_set_hostname(struct cli_def *cli, const char *hostname)
{
    free_z(cli->hostname);
    if (hostname && *hostname)
        cli->hostname = strdup(hostname);
}

void cli_set_promptchar(struct cli_def *cli, char *promptchar)
{
    free_z(cli->promptchar);
    cli->promptchar = strdup(promptchar);
}

static int cli_build_shortest(struct cli_def *cli, struct cli_command *commands)
{
    struct cli_command *c, *p;
    char *cp, *pp;
    int len;

    for (c = commands; c; c = c->next)
    {
        c->unique_len = strlen(c->command);
        if ((c->mode != MODE_ANY && c->mode != cli->mode) ||
            c->privilege > cli->privilege)
            continue;

        c->unique_len = 1;
        for (p = commands; p; p = p->next)
        {
            if (c == p)
                    continue;

            if ((p->mode != MODE_ANY && p->mode != cli->mode) ||
                p->privilege > cli->privilege)
                    continue;

            cp = c->command;
            pp = p->command;
            len = 1;

            while (*cp && *pp && *cp++ == *pp++)
                len++;

            if (len > c->unique_len)
                c->unique_len = len;
        }

        if (c->children)
            cli_build_shortest(cli, c->children);
    }

    return CLI_OK;
}

int cli_set_privilege(struct cli_def *cli, int priv)
{
    int old = cli->privilege;
    cli->privilege = priv;

    if (priv != old)
    {
        cli_set_promptchar(cli, priv == PRIVILEGE_PRIVILEGED ? "# " : "> ");
        cli_build_shortest(cli, cli->commands);
    }

    return old;
}

void cli_set_modestring(struct cli_def *cli, char *modestring)
{
    free_z(cli->modestring);
    if (modestring)
        cli->modestring = strdup(modestring);
}

int cli_set_configmode(struct cli_def *cli, int mode, char *config_desc)
{
    int old = cli->mode;
    cli->mode = mode;

    if (mode != old)
    {
        if (!cli->mode)
        {
            // Not config mode
            cli_set_modestring(cli, NULL);
        }
        else if (config_desc && *config_desc)
        {
            char string[64];
            snprintf(string, sizeof(string), "(config-%s)", config_desc);
            cli_set_modestring(cli, string);
        }
        else
        {
            cli_set_modestring(cli, "(config)");
        }

        cli_build_shortest(cli, cli->commands);
    }

    return old;
}

struct cli_command *cli_register_command_impl(struct cli_def *cli,
    struct cli_command *parent, char *command,
    int (*callback)(struct cli_def *cli, char *, char **, int),
    int privilege, int mode, char *help,
    struct cli_command *c)
{
    struct cli_command *p;

    c->callback = callback;
    c->next = NULL;
    if (!(c->command = strdup(command)))
        return NULL;
    c->parent = parent;
    c->privilege = privilege;
    c->mode = mode;
    if (help)
        if (!(c->help = strdup(help)))
            return NULL;

    if (parent)
    {
        if (!parent->children)
        {
            parent->children = c;
        }
        else
        {
            for (p = parent->children; p && p->next; p = p->next);
            if (p) p->next = c;
        }
    }
    else
    {
        if (!cli->commands)
        {
            cli->commands = c;
        }
        else
        {
            for (p = cli->commands; p && p->next; p = p->next);
            if (p) p->next = c;
        }
    }
    return c;
}

struct cli_command *cli_register_command_sargc(struct cli_def *cli,
    struct cli_command *parent, char *command,
    int (*callback)(struct cli_def *cli, char *, char **, int),
    int privilege, int mode, char *help)
{
    struct cli_command *c;
    struct cli_command *result;

    if (!command) return NULL;
    if (!(c = calloc(sizeof(struct cli_command), 1))) return NULL;

    c->stdargc = 1; // Use standard argc, i.e. command name counts in argc.

    result = cli_register_command_impl(cli, parent, command, callback, privilege, mode,
                                       help, c);

    return result;
}

struct cli_command *cli_register_command(struct cli_def *cli,
    struct cli_command *parent, char *command,
    int (*callback)(struct cli_def *cli, char *, char **, int),
    int privilege, int mode, char *help)
{
    struct cli_command *c;
    struct cli_command *result;

    if (!command) return NULL;
    if (!(c = calloc(sizeof(struct cli_command), 1))) return NULL;

    c->stdargc = 0; // Use libcli argc, i.e. command name does not count in argc.

    result = cli_register_command_impl(cli, parent, command, callback, privilege, mode,
                                       help, c);

    return result;
}



static void cli_free_command(struct cli_command *cmd)
{
    //D("Entered %s", __FUNCTION__);
    struct cli_command *c,*p;

    for (c = cmd->children; c;)
    {
        p = c->next;
        cli_free_command(c);
        c = p;
    }

    if (cmd->command) {
        free(cmd->command);
        cmd->command = NULL;
    }
    if (cmd->help) {
        free(cmd->help);
        cmd->help = NULL;
    }

    free(cmd);
}

int cli_unregister_command(struct cli_def *cli, char *command)
{
    struct cli_command *c, *p = NULL;

    if (!command) return -1;
    if (!cli->commands) return CLI_OK;

    for (c = cli->commands; c; c = c->next)
    {
        if (strcmp(c->command, command) == 0)
        {
            if (p)
                p->next = c->next;
            else
                cli->commands = c->next;

            cli_free_command(c);
            return CLI_OK;
        }
        p = c;
    }

    return CLI_OK;
}

int cli_show_help(struct cli_def *cli, struct cli_command *c)
{
    struct cli_command *p;

    for (p = c; p; p = p->next)
    {
        if (p->command && p->callback && cli->privilege >= p->privilege &&
            (p->mode == cli->mode || p->mode == MODE_ANY))
        {
            cli_error(cli, "  %-20s %s", cli_command_name(cli, p), p->help ? : "");
        }

        if (p->children)
            cli_show_help(cli, p->children);
    }

    return CLI_OK;
}

int cli_int_enable(struct cli_def *cli, UNUSED(char *command), UNUSED(char *argv[]), UNUSED(int argc))
{
    if (cli->privilege == PRIVILEGE_PRIVILEGED)
        return CLI_OK;

    if (!cli->enable_password && !cli->enable_callback)
    {
        /* no password required, set privilege immediately */
        cli_set_privilege(cli, PRIVILEGE_PRIVILEGED);
        cli_set_configmode(cli, MODE_EXEC, NULL);
    }
    else
    {
        /* require password entry */
        cli->state = STATE_ENABLE_PASSWORD;
    }

    return CLI_OK;
}

int cli_int_disable(struct cli_def *cli, UNUSED(char *command), UNUSED(char *argv[]), UNUSED(int argc))
{
    cli_set_privilege(cli, PRIVILEGE_UNPRIVILEGED);
    cli_set_configmode(cli, MODE_EXEC, NULL);
    return CLI_OK;
}

int cli_int_help(struct cli_def *cli, UNUSED(char *command), UNUSED(char *argv[]), UNUSED(int argc))
{
    cli_error(cli, "\nCommands available:");
    cli_show_help(cli, cli->commands);
    return CLI_OK;
}

int cli_int_history(struct cli_def *cli, UNUSED(char *command), UNUSED(char *argv[]), UNUSED(int argc))
{
    int i;

    cli_error(cli, "\nCommand history:");
    for (i = 0; i < MAX_HISTORY; i++)
    {
        if (cli->history[i])
            cli_error(cli, "%3d. %s", i, cli->history[i]);
    }

    return CLI_OK;
}

int cli_int_quit(struct cli_def *cli, UNUSED(char *command), UNUSED(char *argv[]), UNUSED(int argc))
{
    cli_set_privilege(cli, PRIVILEGE_UNPRIVILEGED);
    cli_set_configmode(cli, MODE_EXEC, NULL);
    return CLI_QUIT;
}

int cli_int_exit(struct cli_def *cli, char *command, char *argv[], int argc)
{
    if (cli->mode == MODE_EXEC)
        return cli_int_quit(cli, command, argv, argc);

    if (cli->mode > MODE_CONFIG)
        cli_set_configmode(cli, MODE_CONFIG, NULL);
    else
        cli_set_configmode(cli, MODE_EXEC, NULL);

    cli->service = NULL;
    return CLI_OK;
}

int cli_int_idle_timeout(struct cli_def *cli)
{
    cli_print(cli, "Idle timeout");
    return CLI_QUIT;
}

int cli_int_configure_terminal(struct cli_def *cli, UNUSED(char *command), UNUSED(char *argv[]), UNUSED(int argc))
{
    cli_set_configmode(cli, MODE_CONFIG, NULL);
    return CLI_OK;
}

struct cli_def *cli_init()
{
    struct cli_def *cli;
    struct cli_command *c;

    if (!(cli = calloc(sizeof(struct cli_def), 1)))
        return 0;

    cli->buf_size = 1024;
    if (!(cli->buffer = calloc(cli->buf_size, 1)))
    {
        free_z(cli);
        return 0;
    }

    cli_register_command(cli, 0, "help", cli_int_help, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Show available commands");
    cli_register_command(cli, 0, "quit", cli_int_quit, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Disconnect");
    cli_register_command(cli, 0, "logout", cli_int_quit, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Disconnect");
    cli_register_command(cli, 0, "exit", cli_int_exit, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Exit from current mode");
    cli_register_command(cli, 0, "history", cli_int_history, PRIVILEGE_UNPRIVILEGED, MODE_ANY, "Show a list of previously run commands");
    cli_register_command(cli, 0, "enable", cli_int_enable, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "Turn on privileged commands");
    cli_register_command(cli, 0, "disable", cli_int_disable, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Turn off privileged commands");

    c = cli_register_command(cli, 0, "configure", 0, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Enter configuration mode");
    cli_register_command(cli, c, "terminal", cli_int_configure_terminal, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Configure from the terminal");

    cli->privilege = cli->mode = -1;
    cli_set_privilege(cli, PRIVILEGE_UNPRIVILEGED);
    cli_set_configmode(cli, MODE_EXEC, 0);

    // Default to 1 second timeout intervals
    cli->timeout_tm.tv_sec = 1;
    cli->timeout_tm.tv_usec = 0;

    // Set default idle timeout callback, but no timeout
    cli_set_idle_timeout_callback(cli, 0, cli_int_idle_timeout);
    return cli;
}

void cli_unregister_all(struct cli_def *cli, struct cli_command *command)
{
    struct cli_command *c, *p = NULL;
    //D("Entered %s", __FUNCTION__);

    if (!command) command = cli->commands;
    if (!command) return;

    //D("Cmd: \'%s\'", command->command);
    for (c = command; c; )
    {
        p = c->next;

        // Unregister all child commands
        if (c->children)
            cli_unregister_all(cli, c->children);

        if (c->command) free(c->command);
        if (c->help) free(c->help);
        free(c);

        c = p;
    }
}

#ifdef CLI_NB_ST
void cli_cleanup_ccrs(ccrContext *z)
{
    //D("Entered %s", __FUNCTION__);

    if (*z) {
        ccrContParam = z;
        ccrBeginContext;
        CCR_VAR_LIST
        ccrEndContext(ccrs); // ccrs; Concurrent Co-Routine State

        if (ccrs->cmd) {
            free(ccrs->cmd);
            ccrs->cmd = NULL;
        }
        if (ccrs->negotiate) {
            free(ccrs->negotiate);
            ccrs->negotiate = NULL;
        }

        if (ccrs->username) {
            free(ccrs->username);
            ccrs->username = NULL;
        }
        if (ccrs->password) {
            free(ccrs->password);
            ccrs->password = NULL;
        }

        free(ccrs);
        *z = NULL;
    }
}
#endif

int cli_done(struct cli_def *cli)
{
    struct unp *u = cli->users, *n;

    if (!cli) return CLI_OK;
    cli_free_history(cli);

    // Free all users
    while (u)
    {
        if (u->username) free(u->username);
        if (u->password) free(u->password);
        n = u->next;
        free(u);
        u = n;
    }

    /* free all commands */
    cli_unregister_all(cli, 0);

#ifdef CLI_NB_ST
    cli_cleanup_ccrs(&cli->z);
#endif
    free_z(cli->commandname);
    free_z(cli->modestring);
    free_z(cli->banner);
    free_z(cli->promptchar);
    free_z(cli->hostname);
    free_z(cli->buffer);
    if (cli->client) {
        fclose(cli->client);
    }
    free_z(cli);

    return CLI_OK;
}

static int cli_add_history(struct cli_def *cli, char *cmd)
{
    int i;
    for (i = 0; i < MAX_HISTORY; i++)
    {
        if (!cli->history[i])
        {
            if (i == 0 || strcasecmp(cli->history[i-1], cmd))
            if (!(cli->history[i] = strdup(cmd)))
                return CLI_ERROR;
            return CLI_OK;
        }
    }
    // No space found, drop one off the beginning of the list
    free(cli->history[0]);
    for (i = 0; i < MAX_HISTORY-1; i++)
        cli->history[i] = cli->history[i+1];
    if (!(cli->history[MAX_HISTORY - 1] = strdup(cmd)))
        return CLI_ERROR;
    return CLI_OK;
}

void cli_free_history(struct cli_def *cli)
{
    int i;
    for (i = 0; i < MAX_HISTORY; i++)
    {
        if (cli->history[i])
            free_z(cli->history[i]);
    }
}

static int cli_parse_line(char *line, char *words[], int max_words)
{
    int nwords = 0;
    char *p = line;
    char *word_start = 0;
    int inquote = 0;

    while (*p)
    {
        if (!isspace(*p))
        {
            word_start = p;
            break;
        }
        p++;
    }

    while (nwords < max_words - 1)
    {
        if (!*p || *p == inquote || (word_start && !inquote && (isspace(*p) || *p == '|')))
        {
            if (word_start)
            {
                int len = p - word_start;

                memcpy(words[nwords] = malloc(len + 1), word_start, len);
                words[nwords++][len] = 0;
            }

            if (!*p)
                break;

            if (inquote)
                p++; /* skip over trailing quote */

            inquote = 0;
            word_start = 0;
        }
        else if (*p == '"' || *p == '\'')
        {
            inquote = *p++;
            word_start = p;
        }
        else
        {
            if (!word_start)
            {
                if (*p == '|')
                {
                    if (!(words[nwords++] = strdup("|")))
                        return 0;
                }
                else if (!isspace(*p))
                    word_start = p;
            }

            p++;
        }
    }

    return nwords;
}

static char *join_words(int argc, char **argv)
{
    char *p;
    int len = 0;
    int i;

    for (i = 0; i < argc; i++)
    {
        if (i)
            len += 1;

        len += strlen(argv[i]);
    }

    p = malloc(len + 1);
    p[0] = 0;

    for (i = 0; i < argc; i++)
    {
        if (i)
            strcat(p, " ");

        strcat(p, argv[i]);
    }

    return p;
}

static int cli_find_command(struct cli_def *cli, struct cli_command *commands, int num_words, char *words[], int start_word, int filters[])
{
    struct cli_command *c, *again = NULL;
    int c_words = num_words;

    if (filters[0])
        c_words = filters[0];

    // Deal with ? for help
    if (!words[start_word])
        return CLI_ERROR;

    if (words[start_word][strlen(words[start_word]) - 1] == '?')
    {
        int l = strlen(words[start_word])-1;

        if (commands->parent && commands->parent->callback)
            cli_error(cli, "%-20s %s", cli_command_name(cli, commands->parent),  commands->parent->help ? : "");

        for (c = commands; c; c = c->next)
        {
            if (strncasecmp(c->command, words[start_word], l) == 0
                && (c->callback || c->children)
                && cli->privilege >= c->privilege
                && (c->mode == cli->mode || c->mode == MODE_ANY))
                    cli_error(cli, "  %-20s %s", c->command, c->help ? : "");
        }

        return CLI_OK;
    }

    for (c = commands; c; c = c->next)
    {
        if (cli->privilege < c->privilege)
            continue;

        if (strncasecmp(c->command, words[start_word], c->unique_len))
            continue;

        if (strncasecmp(c->command, words[start_word], strlen(words[start_word])))
            continue;

        AGAIN:
        if (c->mode == cli->mode || c->mode == MODE_ANY)
        {
            int rc = CLI_OK;
            int f;
            struct cli_filter **filt = &cli->filters;

            // Found a word!
            if (!c->children)
            {
                // Last word
                if (!c->callback)
                {
                    cli_error(cli, "No callback for \"%s\"", cli_command_name(cli, c));
                    return CLI_ERROR;
                }
            }
            else
            {
                if (start_word == c_words - 1)
                {
                    if (c->callback)
                        goto CORRECT_CHECKS;

                    cli_error(cli, "Incomplete command");
                    return CLI_ERROR;
                }
                rc = cli_find_command(cli, c->children, num_words, words, start_word + 1, filters);
                if (rc == CLI_ERROR_ARG)
                {
                    if (c->callback)
                    {
                        rc = CLI_OK;
                        goto CORRECT_CHECKS;
                    }
                    else
                    {
                        cli_error(cli, "Invalid %s \"%s\"", commands->parent ? "argument" : "command", words[start_word]);
                    }
                }
                return rc;
            }

            if (!c->callback)
            {
                cli_error(cli, "Internal server error processing \"%s\"", cli_command_name(cli, c));
                return CLI_ERROR;
            }

            CORRECT_CHECKS:
            for (f = 0; rc == CLI_OK && filters[f]; f++)
            {
                int n = num_words;
                char **argv;
                int argc;
                int len;

                if (filters[f+1])
                n = filters[f+1];

                if (filters[f] == n - 1)
                {
                    cli_error(cli, "Missing filter");
                    return CLI_ERROR;
                }

                argv = words + filters[f] + 1;
                argc = n - (filters[f] + 1);
                len = strlen(argv[0]);
                if (argv[argc - 1][strlen(argv[argc - 1]) - 1] == '?')
                {
                    if (argc == 1)
                    {
                        int i;

                        for(i = 0; filter_cmds[i].cmd; i++)
                        {
                            cli_error(cli, "  %-20s %s", filter_cmds[i].cmd, filter_cmds[i].help );
                        }
                    }
                    else
                    {
                        if (argv[0][0] != 'c') // count
                            cli_error(cli, "  WORD");

                        if (argc > 2 || argv[0][0] == 'c') // count
                            cli_error(cli, "  <cr>");
                    }

                    return CLI_OK;
                }

                if (argv[0][0] == 'b' && len < 3) // [beg]in, [bet]ween
                {
                    cli_error(cli, "Ambiguous filter \"%s\" (begin, between)", argv[0]);
                    return CLI_ERROR;
                }
                *filt = calloc(sizeof(struct cli_filter), 1);

                if (!strncmp("include", argv[0], len) ||
                    !strncmp("exclude", argv[0], len) ||
                    !strncmp("grep", argv[0], len) ||
                    !strncmp("egrep", argv[0], len))
                        rc = cli_match_filter_init(cli, argc, argv, *filt);
                else if (!strncmp("begin", argv[0], len) ||
                    !strncmp("between", argv[0], len))
                        rc = cli_range_filter_init(cli, argc, argv, *filt);
                else if (!strncmp("count", argv[0], len))
                    rc = cli_count_filter_init(cli, argc, argv, *filt);
                else
                {
                    cli_error(cli, "Invalid filter \"%s\"", argv[0]);
                    rc = CLI_ERROR;
                }

                if (rc == CLI_OK)
                {
                    filt = &(*filt)->next;
                }
                else
                {
                    free(*filt);
                    *filt = 0;
                }
            }

            if (rc == CLI_OK) {
                if (c->stdargc) {
                    rc = c->callback(cli, cli_command_name(cli, c),
                                     words + start_word,
                                     c_words - start_word);
                } else {
                    rc = c->callback(cli, cli_command_name(cli, c),
                                     words + start_word + 1,
                                     c_words - start_word - 1);
                }
            }

            while (cli->filters)
            {
                struct cli_filter *filt = cli->filters;

                // call one last time to clean up
                filt->filter(cli, NULL, filt->data);
                cli->filters = filt->next;
                free(filt);
            }

            if (rc == CLI_OK) {
                cli_print(cli, "\nOK");
            } else {
                cli_print(cli, "\nERROR: %d (%s)", rc, cli_rc_to_str(rc));
            }
            return rc;
        }
        else if (cli->mode > MODE_CONFIG && c->mode == MODE_CONFIG)
        {
            // command matched but from another mode,
            // remember it if we fail to find correct command
            again = c;
        }
    }

    // drop out of config submode if we have matched command on MODE_CONFIG
    if (again)
    {
        c = again;
        cli_set_configmode(cli, MODE_CONFIG, NULL);
        goto AGAIN;
    }

    if (start_word == 0)
        cli_error(cli, "Invalid %s \"%s\"", commands->parent ? "argument" : "command", words[start_word]);

    return CLI_ERROR_ARG;
}

int cli_run_command(struct cli_def *cli, char *command)
{
    int r;
    unsigned int num_words, i, f;
    char *words[CLI_MAX_LINE_WORDS] = {0};
    int filters[CLI_MAX_LINE_WORDS] = {0};

    if (!command) return CLI_ERROR;
    while (isspace(*command))
        command++;

    if (!*command) return CLI_OK;

    num_words = cli_parse_line(command, words, CLI_MAX_LINE_WORDS);
    for (i = f = 0; i < num_words && f < CLI_MAX_LINE_WORDS - 1; i++)
    {
        if (words[i][0] == '|')
        filters[f++] = i;
    }

    filters[f] = 0;

    if (num_words)
        r = cli_find_command(cli, cli->commands, num_words, words, 0, filters);
    else
        r = CLI_ERROR;

    for (i = 0; i < num_words; i++)
        free(words[i]);

    if (r == CLI_QUIT)
        return r;

    return CLI_OK;
}

static int cli_get_completions(struct cli_def *cli, char *command, char **completions, int max_completions)
{
    struct cli_command *c;
    struct cli_command *n;
    int num_words, i, k=0;
    char *words[CLI_MAX_LINE_WORDS] = {0};
    int filter = 0;

    if (!command) return 0;
    while (isspace(*command))
        command++;

    num_words = cli_parse_line(command, words, sizeof(words)/sizeof(words[0]));
    if (!command[0] || command[strlen(command)-1] == ' ')
        num_words++;

    if (!num_words)
            return 0;

    for (i = 0; i < num_words; i++)
    {
        if (words[i] && words[i][0] == '|')
            filter = i;
    }

    if (filter) // complete filters
    {
        unsigned len = 0;

        if (filter < num_words - 1) // filter already completed
            return 0;

        if (filter == num_words - 1)
            len = strlen(words[num_words-1]);

        for (i = 0; filter_cmds[i].cmd && k < max_completions; i++)
            if (!len || (len < strlen(filter_cmds[i].cmd)
                && !strncmp(filter_cmds[i].cmd, words[num_words - 1], len)))
                    completions[k++] = filter_cmds[i].cmd;

        completions[k] = NULL;
        for (i = 0; i < CLI_MAX_LINE_WORDS; i++) {
            if (words[i]) {
                free(words[i]);
            }
        }
        return k;
    }

    for (c = cli->commands, i = 0; c && i < num_words && k < max_completions; c = n)
    {
        n = c->next;

        if (cli->privilege < c->privilege)
            continue;

        if (c->mode != cli->mode && c->mode != MODE_ANY)
            continue;

        if (words[i] && strncasecmp(c->command, words[i], strlen(words[i])))
            continue;

        if (i < num_words - 1)
        {
            if (strlen(words[i]) < c->unique_len)
                    continue;

            n = c->children;
            i++;
            continue;
        }

        completions[k++] = c->command;
    }

    for (i = 0; i < CLI_MAX_LINE_WORDS; i++) {
        if (words[i]) {
            free(words[i]);
        }
    }

    return k;
}

static void cli_clear_line(int sockfd, char *cmd, int l, int cursor)
{
    int i;
    if (cursor < l) for (i = 0; i < (l - cursor); i++) write(sockfd, " ", 1);
    for (i = 0; i < l; i++) cmd[i] = '\b';
    for (; i < l * 2; i++) cmd[i] = ' ';
    for (; i < l * 3; i++) cmd[i] = '\b';
    write(sockfd, cmd, i);
    memset(cmd, 0, i);
    l = cursor = 0;
}

void cli_reprompt(struct cli_def *cli)
{
    if (!cli) return;
    cli->showprompt = 1;
}

void cli_regular(struct cli_def *cli, int (*callback)(struct cli_def *cli))
{
    if (!cli) return;
    cli->regular_callback = callback;
}

void cli_regular_interval(struct cli_def *cli, int seconds)
{
    if (seconds < 1) seconds = 1;
    cli->timeout_tm.tv_sec = seconds;
    cli->timeout_tm.tv_usec = 0;
}

#define DES_PREFIX "{crypt}"        /* to distinguish clear text from DES crypted */
#define MD5_PREFIX "$1$"

static int pass_matches(char *pass, char *try)
{
    int des;
    if ((des = !strncasecmp(pass, DES_PREFIX, sizeof(DES_PREFIX)-1)))
        pass += sizeof(DES_PREFIX)-1;

#ifndef WIN32
    /*
     * TODO - find a small crypt(3) function for use on windows
     */
    //if (des || !strncmp(pass, MD5_PREFIX, sizeof(MD5_PREFIX)-1))
    //    try = crypt(try, pass);
#endif

    return !strcmp(pass, try);
}

#define CTRL(c) (c - '@')

static int show_prompt(struct cli_def *cli, int sockfd)
{
    int len = 0;

    if (cli->hostname)
        len += write(sockfd, cli->hostname, strlen(cli->hostname));

    if (cli->modestring)
        len += write(sockfd, cli->modestring, strlen(cli->modestring));

    return len + write(sockfd, cli->promptchar, strlen(cli->promptchar));
}
#ifndef CLI_NB_ST
int cli_loop(struct cli_def *cli, int sockfd)
{
    unsigned char c;
    int n, l, oldl = 0, is_telnet_option = 0, skip = 0, esc = 0;
    int cursor = 0, insertmode = 1;
    char *cmd = NULL, *oldcmd = 0;
    char *username = NULL, *password = NULL;
    char *negotiate =
        "\xFF\xFB\x03"
        "\xFF\xFB\x01"
        "\xFF\xFD\x03"
        "\xFF\xFD\x01";

    cli_build_shortest(cli, cli->commands);
    cli->state = STATE_LOGIN;

    cli_free_history(cli);
    write(sockfd, negotiate, strlen(negotiate));

    if ((cmd = malloc(CLI_MAX_LINE_LENGTH)) == NULL)
        return CLI_ERROR;

#ifdef WIN32
    /*
     * OMG, HACK
     */
    if (!(cli->client = fdopen(_open_osfhandle(sockfd,0), "w+")))
        return CLI_ERROR;
    cli->client->_file = sockfd;
#else
    if (!(cli->client = fdopen(sockfd, "w+")))
        return CLI_ERROR;
#endif

    setbuf(cli->client, NULL);
    if (cli->banner)
        cli_error(cli, "%s", cli->banner);

    // Set the last action now so we don't time immediately
    if (cli->idle_timeout)
        time(&cli->last_action);

    /* start off in unprivileged mode */
    cli_set_privilege(cli, PRIVILEGE_UNPRIVILEGED);
    cli_set_configmode(cli, MODE_EXEC, NULL);

    /* no auth required? */
    if (!cli->users && !cli->auth_callback)
        cli->state = STATE_NORMAL;

    while (1)
    {
        signed int in_history = 0;
        int lastchar = 0;
        struct timeval tm;

        cli->showprompt = 1;

        if (oldcmd)
        {
            l = cursor = oldl;
            oldcmd[l] = 0;
            cli->showprompt = 1;
            oldcmd = NULL;
            oldl = 0;
        }
        else
        {
            memset(cmd, 0, CLI_MAX_LINE_LENGTH);
            l = 0;
            cursor = 0;
        }

        memcpy(&tm, &cli->timeout_tm, sizeof(tm));

        while (1)
        {
            int sr;
            fd_set r;
            if (cli->showprompt)
            {
                if (cli->state != STATE_PASSWORD && cli->state != STATE_ENABLE_PASSWORD)
                    write(sockfd, "\r\n", 2);

                switch (cli->state)
                {
                    case STATE_LOGIN:
                        write(sockfd, "Username: ", strlen("Username: "));
                        break;

                    case STATE_PASSWORD:
                        write(sockfd, "Password: ", strlen("Password: "));
                        break;

                    case STATE_NORMAL:
                    case STATE_ENABLE:
                        show_prompt(cli, sockfd);
                        write(sockfd, cmd, l);
                        if (cursor < l)
                        {
                            int n = l - cursor;
                            while (n--)
                                write(sockfd, "\b", 1);
                        }
                        break;

                    case STATE_ENABLE_PASSWORD:
                        write(sockfd, "Password: ", strlen("Password: "));
                        break;

                }

                cli->showprompt = 0;
            }

            FD_ZERO(&r);
            FD_SET(sockfd, &r);

            if ((sr = select(sockfd + 1, &r, NULL, NULL, &tm)) < 0)
            {
                /* select error */
                if (errno == EINTR)
                    continue;

                perror("select");
                l = -1;
                break;
            }

            if (sr == 0)
            {
                /* timeout every second */
                if (cli->regular_callback && cli->regular_callback(cli) != CLI_OK)
                {
                    l = -1;
                    break;
                }

                if (cli->idle_timeout)
                {
                    if (time(NULL) - cli->last_action >= cli->idle_timeout)
                    {
                        if (cli->idle_timeout_callback)
                        {
                            // Call the callback and continue on if successful
                            if (cli->idle_timeout_callback(cli) == CLI_OK)
                            {
                                // Reset the idle timeout counter
                                time(&cli->last_action);
                                continue;
                            }
                        }
                        // Otherwise, break out of the main loop
                        l = -1;
                        break;
                    }
                }

                memcpy(&tm, &cli->timeout_tm, sizeof(tm));
                continue;
            }

            if ((n = read(sockfd, &c, 1)) < 0)
            {
                if (errno == EINTR)
                    continue;

                perror("read");
                l = -1;
                break;
            }

            if (cli->idle_timeout)
                time(&cli->last_action);

            if (n == 0)
            {
                l = -1;
                break;
            }

            if (skip)
            {
                skip--;
                continue;
            }

            if (c == 255 && !is_telnet_option)
            {
                is_telnet_option++;
                continue;
            }

            if (is_telnet_option)
            {
                if (c >= 251 && c <= 254)
                {
                    is_telnet_option = c;
                    continue;
                }

                if (c != 255)
                {
                    is_telnet_option = 0;
                    continue;
                }

                is_telnet_option = 0;
            }

            /* handle ANSI arrows */
            if (esc)
            {
                if (esc == '[')
                {
                    /* remap to readline control codes */
                    switch (c)
                    {
                        case 'A': /* Up */
                            c = CTRL('P');
                            break;

                        case 'B': /* Down */
                            c = CTRL('N');
                            break;

                        case 'C': /* Right */
                            c = CTRL('F');
                            break;

                        case 'D': /* Left */
                            c = CTRL('B');
                            break;

                        default:
                            c = 0;
                    }

                    esc = 0;
                }
                else
                {
                    esc = (c == '[') ? c : 0;
                    continue;
                }
            }

            if (c == 0) continue;
            if (c == '\n') continue;

            if (c == '\r')
            {
                if (cli->state != STATE_PASSWORD && cli->state != STATE_ENABLE_PASSWORD)
                    write(sockfd, "\r\n", 2);
                break;
            }

            if (c == 27)
            {
                esc = 1;
                continue;
            }

            if (c == CTRL('C'))
            {
                write(sockfd, "\a", 1);
                continue;
            }

            /* back word, backspace/delete */
            if (c == CTRL('W') || c == CTRL('H') || c == 0x7f)
            {
                int back = 0;

                if (c == CTRL('W')) /* word */
                {
                    int nc = cursor;

                    if (l == 0 || cursor == 0)
                        continue;

                    while (nc && cmd[nc - 1] == ' ')
                    {
                        nc--;
                        back++;
                    }

                    while (nc && cmd[nc - 1] != ' ')
                    {
                        nc--;
                        back++;
                    }
                }
                else /* char */
                {
                    if (l == 0 || cursor == 0)
                    {
                        write(sockfd, "\a", 1);
                        continue;
                    }

                    back = 1;
                }

                if (back)
                {
                    while (back--)
                    {
                        if (l == cursor)
                        {
                            cmd[--cursor] = 0;
                            if (cli->state != STATE_PASSWORD && cli->state != STATE_ENABLE_PASSWORD)
                                write(sockfd, "\b \b", 3);
                        }
                        else
                        {
                            int i;
                            cursor--;
                            if (cli->state != STATE_PASSWORD && cli->state != STATE_ENABLE_PASSWORD)
                            {
                                for (i = cursor; i <= l; i++) cmd[i] = cmd[i+1];
                                write(sockfd, "\b", 1);
                                write(sockfd, cmd + cursor, strlen(cmd + cursor));
                                write(sockfd, " ", 1);
                                for (i = 0; i <= (int)strlen(cmd + cursor); i++)
                                    write(sockfd, "\b", 1);
                            }
                        }
                        l--;
                    }

                    continue;
                }
            }

            /* redraw */
            if (c == CTRL('L'))
            {
                int i;
                int cursorback = l - cursor;

                if (cli->state == STATE_PASSWORD || cli->state == STATE_ENABLE_PASSWORD)
                    continue;

                write(sockfd, "\r\n", 2);
                show_prompt(cli, sockfd);
                write(sockfd, cmd, l);

                for (i = 0; i < cursorback; i++)
                    write(sockfd, "\b", 1);

                continue;
            }

            /* clear line */
            if (c == CTRL('U'))
            {
                if (cli->state == STATE_PASSWORD || cli->state == STATE_ENABLE_PASSWORD)
                    memset(cmd, 0, l);
                else
                    cli_clear_line(sockfd, cmd, l, cursor);

                l = cursor = 0;
                continue;
            }

            /* kill to EOL */
            if (c == CTRL('K'))
            {
                if (cursor == l)
                    continue;

                if (cli->state != STATE_PASSWORD && cli->state != STATE_ENABLE_PASSWORD)
                {
                    int c;
                    for (c = cursor; c < l; c++)
                        write(sockfd, " ", 1);

                    for (c = cursor; c < l; c++)
                        write(sockfd, "\b", 1);
                }

                memset(cmd + cursor, 0, l - cursor);
                l = cursor;
                continue;
            }

            /* EOT */
            if (c == CTRL('D'))
            {
                if (cli->state == STATE_PASSWORD || cli->state == STATE_ENABLE_PASSWORD)
                    break;

                if (l)
                    continue;

                l = -1;
                break;
            }

            /* disable */
            if (c == CTRL('Z'))
            {
                if (cli->mode != MODE_EXEC)
                {
                    cli_clear_line(sockfd, cmd, l, cursor);
                    cli_set_configmode(cli, MODE_EXEC, NULL);
                    cli->showprompt = 1;
                }

                continue;
            }

            /* TAB completion */
            if (c == CTRL('I'))
            {
                char *completions[CLI_MAX_LINE_WORDS];
                int num_completions = 0;

                if (cli->state == STATE_LOGIN || cli->state == STATE_PASSWORD || cli->state == STATE_ENABLE_PASSWORD)
                    continue;

                if (cursor != l) continue;

                num_completions = cli_get_completions(cli, cmd, completions, CLI_MAX_LINE_WORDS);
                if (num_completions == 0)
                {
                    write(sockfd, "\a", 1);
                }
                else if (num_completions == 1)
                {
                    // Single completion
                    for (; l > 0; l--, cursor--)
                    {
                        if (cmd[l-1] == ' ' || cmd[l-1] == '|')
                            break;
                        write(sockfd, "\b", 1);
                    }
                    strcpy((cmd + l), completions[0]);
                    l += strlen(completions[0]);
                    cmd[l++] = ' ';
                    cursor = l;
                    write(sockfd, completions[0], strlen(completions[0]));
                    write(sockfd, " ", 1);
                }
                else if (lastchar == CTRL('I'))
                {
                    // double tab
                    int i;
                    write(sockfd, "\r\n", 2);
                    for (i = 0; i < num_completions; i++)
                    {
                        write(sockfd, completions[i], strlen(completions[i]));
                        if (i % 4 == 3)
                            write(sockfd, "\r\n", 2);
                        else
                            write(sockfd, "     ", 1);
                    }
                    if (i % 4 != 3) write(sockfd, "\r\n", 2);
                        cli->showprompt = 1;
                }
                else
                {
                    // More than one completion
                    lastchar = c;
                    write(sockfd, "\a", 1);
                }
                continue;
            }

            /* history */
            if (c == CTRL('P') || c == CTRL('N'))
            {
                int history_found = 0;

                if (cli->state == STATE_LOGIN || cli->state == STATE_PASSWORD || cli->state == STATE_ENABLE_PASSWORD)
                    continue;

                if (c == CTRL('P')) // Up
                {
                    in_history--;
                    if (in_history < 0)
                    {
                        for (in_history = MAX_HISTORY-1; in_history >= 0; in_history--)
                        {
                            if (cli->history[in_history])
                            {
                                history_found = 1;
                                break;
                            }
                        }
                    }
                    else
                    {
                        if (cli->history[in_history]) history_found = 1;
                    }
                }
                else // Down
                {
                    in_history++;
                    if (in_history >= MAX_HISTORY || !cli->history[in_history])
                    {
                        int i = 0;
                        for (i = 0; i < MAX_HISTORY; i++)
                        {
                            if (cli->history[i])
                            {
                                in_history = i;
                                history_found = 1;
                                break;
                            }
                        }
                    }
                    else
                    {
                        if (cli->history[in_history]) history_found = 1;
                    }
                }
                if (history_found && cli->history[in_history])
                {
                    // Show history item
                    cli_clear_line(sockfd, cmd, l, cursor);
                    memset(cmd, 0, CLI_MAX_LINE_LENGTH);
                    strncpy(cmd, cli->history[in_history], CLI_MAX_LINE_LENGTH - 1);
                    l = cursor = strlen(cmd);
                    write(sockfd, cmd, l);
                }

                continue;
            }

            /* left/right cursor motion */
            if (c == CTRL('B') || c == CTRL('F'))
            {
                if (c == CTRL('B')) /* Left */
                {
                    if (cursor)
                    {
                        if (cli->state != STATE_PASSWORD && cli->state != STATE_ENABLE_PASSWORD)
                            write(sockfd, "\b", 1);

                        cursor--;
                    }
                }
                else /* Right */
                {
                    if (cursor < l)
                    {
                        if (cli->state != STATE_PASSWORD && cli->state != STATE_ENABLE_PASSWORD)
                            write(sockfd, &cmd[cursor], 1);

                        cursor++;
                    }
                }

                continue;
            }

            /* start of line */
            if (c == CTRL('A'))
            {
                if (cursor)
                {
                    if (cli->state != STATE_PASSWORD && cli->state != STATE_ENABLE_PASSWORD)
                    {
                        write(sockfd, "\r", 1);
                        show_prompt(cli, sockfd);
                    }

                    cursor = 0;
                }

                continue;
            }

            /* end of line */
            if (c == CTRL('E'))
            {
                if (cursor < l)
                {
                    if (cli->state != STATE_PASSWORD && cli->state != STATE_ENABLE_PASSWORD)
                        write(sockfd, &cmd[cursor], l - cursor);

                    cursor = l;
                }

                continue;
            }

            /* normal character typed */
            if (cursor == l)
            {
                 /* append to end of line */
                cmd[cursor] = c;
                if (l < CLI_MAX_LINE_LENGTH - 1)
                {
                    l++;
                    cursor++;
                }
                else
                {
                    write(sockfd, "\a", 1);
                    continue;
                }
            }
            else
            {
                // Middle of text
                if (insertmode)
                {
                    int i;
                    // Move everything one character to the right
                    if (l >= CLI_MAX_LINE_LENGTH - 2) l--;
                    for (i = l; i >= cursor; i--)
                        cmd[i + 1] = cmd[i];
                    // Write what we've just added
                    cmd[cursor] = c;

                    write(sockfd, &cmd[cursor], l - cursor + 1);
                    for (i = 0; i < (l - cursor + 1); i++)
                        write(sockfd, "\b", 1);
                    l++;
                }
                else
                {
                    cmd[cursor] = c;
                }
                cursor++;
            }

            if (cli->state != STATE_PASSWORD && cli->state != STATE_ENABLE_PASSWORD)
            {
                if (c == '?' && cursor == l)
                {
                    write(sockfd, "\r\n", 2);
                    oldcmd = cmd;
                    oldl = cursor = l - 1;
                    break;
                }
                write(sockfd, &c, 1);
            }

            oldcmd = 0;
            oldl = 0;
            lastchar = c;
        }

        if (l < 0) break;

        if (cli->state == STATE_LOGIN)
        {
            if (l == 0) continue;

            /* require login */
            free_z(username);
            if (!(username = strdup(cmd)))
                return 0;
            cli->state = STATE_PASSWORD;
            cli->showprompt = 1;
        }
        else if (cli->state == STATE_PASSWORD)
        {
            /* require password */
            int allowed = 0;

            free_z(password);
            if (!(password = strdup(cmd)))
                return 0;
            if (cli->auth_callback)
            {
                if (cli->auth_callback(username, password) == CLI_OK)
                    allowed++;
            }

            if (!allowed)
            {
                struct unp *u;
                for (u = cli->users; u; u = u->next)
                {
                    if (!strcmp(u->username, username) && pass_matches(u->password, password))
                    {
                        allowed++;
                        break;
                    }
                }
            }

            if (allowed)
            {
                cli_error(cli, "");
                cli->state = STATE_NORMAL;
            }
            else
            {
                cli_error(cli, "\n\nAccess denied");
                free_z(username);
                free_z(password);
                cli->state = STATE_LOGIN;
            }

            cli->showprompt = 1;
        }
        else if (cli->state == STATE_ENABLE_PASSWORD)
        {
            int allowed = 0;
            if (cli->enable_password)
            {
                /* check stored static enable password */
                if (pass_matches(cli->enable_password, cmd))
                    allowed++;
            }

            if (!allowed && cli->enable_callback)
            {
                /* check callback */
                if (cli->enable_callback(cmd))
                    allowed++;
            }

            if (allowed)
            {
                cli->state = STATE_ENABLE;
                cli_set_privilege(cli, PRIVILEGE_PRIVILEGED);
            }
            else
            {
                cli_error(cli, "\n\nAccess denied");
                cli->state = STATE_NORMAL;
            }
        }
        else
        {
            if (l == 0) continue;
            if (cmd[l - 1] != '?' && strcasecmp(cmd, "history") != 0)
                cli_add_history(cli, cmd);

            if (cli_run_command(cli, cmd) == CLI_QUIT)
                break;
        }

        // Update the last_action time now as the last command run could take a
        // long time to return
        if (cli->idle_timeout)
            time(&cli->last_action);
    }

    cli_free_history(cli);
    free_z(username);
    free_z(password);
    free_z(cmd);

    fclose(cli->client);
    cli->client = 0;
    return CLI_OK;
}
#else

int cli_process_event(struct cli_def *cli)
{
    ccrContParam = &cli->z;

    ccrBeginContext;
    CCR_VAR_LIST
    ccrEndContext(ccrs); // ccrs; Concurrent Co-Routine State


    int retval = CLI_UNINITIALIZED;
    ccrBegin(ccrs);
    cli->callback_only_on_fd_readable = 0;
    /* fprintf(stdout, "F: %s, L: %d, Got revents, EV_READ: %d, EV_WRITE: %d\n", */
    /*         __FILE__, */
    /*         __LINE__, */
    /*         revents & EV_READ, */
    /*         revents & EV_WRITE); */

    ccrs->oldl = 0;
    ccrs->is_telnet_option = 0;
    ccrs->skip = 0;
    ccrs->esc = 0;
    ccrs->cursor = 0;
    ccrs->insertmode = 1;
    ccrs->cmd = NULL;
    ccrs->oldcmd = 0;
    ccrs->username = NULL;
    ccrs->password = NULL;
    ccrs->negotiate = strdup(
        "\xFF\xFB\x03"
        "\xFF\xFB\x01"
        "\xFF\xFD\x03"
        "\xFF\xFD\x01");
    if (!ccrs->negotiate) {
        retval = CLI_QUIT;
        goto CCR_FINISH;
    }

    ccrs->nwanted = 0;
    ccrs->nwritten = 0;

    cli_build_shortest(cli, cli->commands);
    cli->state = STATE_LOGIN;

    cli_free_history(cli);


    ccrs->nwanted = strlen(ccrs->negotiate);
    ccrs->nwritten = write(cli->fd, ccrs->negotiate, ccrs->nwanted);

    if (ccrs->nwritten < 0) {
        if (errno != EWOULDBLOCK) {
            perror("Unknown error");
            assert(0);
        } else {
            fprintf(stderr, "Error, write would have blocked\n");
            assert(0);
        }
    } else if (ccrs->nwritten < ccrs->nwanted) {
        fprintf(stderr, "Error, only partial write. nritten %ld, nwanted %ld\n",
                (long int)ccrs->nwritten, (long int)ccrs->nwanted);
        assert(0);
    }

    ccrReturn(CLI_OK);
    /* fprintf(stdout, "F: %s, L: %d, Got revents, EV_READ: %d, EV_WRITE: %d\n", */
    /*         __FILE__, */
    /*         __LINE__, */
    /*         revents & EV_READ, */
    /*         revents & EV_WRITE); */

    if ((ccrs->cmd = malloc(CLI_MAX_LINE_LENGTH)) == NULL) {
        retval = CLI_QUIT;
        goto CCR_FINISH;
    }


#ifdef WIN32
    /*
     * OMG, HACK
     */
    if (!(cli->client = fdopen(_open_osfhandle(cli->fd,0), "w+")))
        ccrReturn(CLI_QUIT);
    cli->client->_file = cli->fd;
#else
    if (!(cli->client = fdopen(cli->fd, "w+")))
        ccrReturn(CLI_QUIT);
#endif

    setbuf(cli->client, NULL);
    if (cli->banner)
        cli_error(cli, "%s", cli->banner);

    // Set the last action now so we don't time immediately
    if (cli->idle_timeout)
        time(&cli->last_action);

    /* start off in unprivileged mode */
    cli_set_privilege(cli, PRIVILEGE_UNPRIVILEGED);
    cli_set_configmode(cli, MODE_EXEC, NULL);

    /* no auth required? */
    if (!cli->users && !cli->auth_callback)
        cli->state = STATE_NORMAL;

    while (1) // Outer while(1) loop
    {
        ccrReturn(CLI_OK); // General yield, catches all breaks and
                           // continues that end up here

        /* fprintf(stdout, "(outer while()) F: %s, L: %d, Got revents, EV_READ: %d, EV_WRITE: %d\n", */
        /*     __FILE__, */
        /*     __LINE__, */
        /*     revents & EV_READ, */
        /*     revents & EV_WRITE); */


        ccrs->in_history = 0;
        ccrs->lastchar = 0;

        cli->showprompt = 1;

        if (ccrs->oldcmd)
        {
            ccrs->l = ccrs->cursor = ccrs->oldl;
            ccrs->oldcmd[ccrs->l] = 0;
            cli->showprompt = 1;
            ccrs->oldcmd = NULL;
            ccrs->oldl = 0;
        }
        else
        {
            memset(ccrs->cmd, 0, CLI_MAX_LINE_LENGTH);
            ccrs->l = 0;
            ccrs->cursor = 0;
        }

        //memcpy(&tm, &cli->timeout_tm, sizeof(tm));

        while (1) // Inner while(1) loop
        {
            ccrReturn(CLI_OK); // General yield, will yield after all
                               // continue statements that take us here

            /* fprintf(stdout, "(inner while()) F: %s, L: %d, Got revents, " */
            /*         "EV_READ: %d, EV_WRITE: %d\n", */
            /*         __FILE__, */
            /*         __LINE__, */
            /*         revents & EV_READ, */
            /*         revents & EV_WRITE); */

            if (cli->showprompt)
            {
                if (cli->state != STATE_PASSWORD && cli->state != STATE_ENABLE_PASSWORD)
                    write(cli->fd, "\r\n", 2);

                switch (cli->state)
                {
                    case STATE_LOGIN:
                        write(cli->fd, "Username: ", strlen("Username: "));
                        break;

                    case STATE_PASSWORD:
                        write(cli->fd, "Password: ", strlen("Password: "));
                        break;

                    case STATE_NORMAL:
                    case STATE_ENABLE:
                        show_prompt(cli, cli->fd);
                        write(cli->fd, ccrs->cmd, ccrs->l);
                        if (ccrs->cursor < ccrs->l)
                        {
                            int n = ccrs->l - ccrs->cursor;
                            while (n--)
                                write(cli->fd, "\b", 1);
                        }
                        break;

                    case STATE_ENABLE_PASSWORD:
                        write(cli->fd, "Password: ", strlen("Password: "));
                        break;

                }

                cli->showprompt = 0;
                ccrReturn(CLI_OK); // yield...
            }


            cli->callback_only_on_fd_readable = 1;
            if ((cli->revents & EV_READ) == 0) {
                ccrReturn(CLI_OK);
            }

            if ((ccrs->n = read(cli->fd, &ccrs->c, 1)) < 0)
            {
                if (errno == EINTR) // Interrupted by signal
                    continue;

                perror("read");
                ccrs->l = -1;
                ccrReturn(CLI_QUIT);
            }

            cli->callback_only_on_fd_readable = 0;

            //if (cli->idle_timeout)
            //    time(&cli->last_action);

            if (ccrs->n == 0)
            {
                ccrs->l = -1;
                retval = CLI_QUIT;
                goto CCR_FINISH;
            }

            if (ccrs->skip)
            {
                ccrs->skip--;
                continue;
            }

            if (ccrs->c == 255 && !ccrs->is_telnet_option)
            {
                ccrs->is_telnet_option++;
                continue;
            }

            if (ccrs->is_telnet_option)
            {
                if (ccrs->c >= 251 && ccrs->c <= 254)
                {
                    ccrs->is_telnet_option = ccrs->c;
                    continue;
                }

                if (ccrs->c != 255)
                {
                    ccrs->is_telnet_option = 0;
                    continue;
                }

                ccrs->is_telnet_option = 0;
            }

            /* handle ANSI arrows */
            if (ccrs->esc)
            {
                if (ccrs->esc == '[')
                {
                    /* remap to readline control codes */
                    switch (ccrs->c)
                    {
                        case 'A': /* Up */
                            ccrs->c = CTRL('P');
                            break;

                        case 'B': /* Down */
                            ccrs->c = CTRL('N');
                            break;

                        case 'C': /* Right */
                            ccrs->c = CTRL('F');
                            break;

                        case 'D': /* Left */
                            ccrs->c = CTRL('B');
                            break;

                        default:
                            ccrs->c = 0;
                    }

                    ccrs->esc = 0;
                }
                else
                {
                    ccrs->esc = (ccrs->c == '[') ? ccrs->c : 0;
                    continue;
                }
            }

            if (ccrs->c == 0) continue;
            if (ccrs->c == '\n') continue;

            if (ccrs->c == '\r')
            {
                if (cli->state != STATE_PASSWORD &&
                    cli->state != STATE_ENABLE_PASSWORD)
                {
                    write(cli->fd, "\r\n", 2);
                }
                break;
            }

            if (ccrs->c == 27)
            {
                ccrs->esc = 1;
                continue;
            }

            if (ccrs->c == CTRL('C'))
            {
                write(cli->fd, "\a", 1);
                continue;
            }

            /* back word, backspace/delete */
            if (ccrs->c == CTRL('W') || ccrs->c == CTRL('H') || ccrs->c == 0x7f)
            {
                int back = 0;

                if (ccrs->c == CTRL('W')) /* word */
                {
                    int nc = ccrs->cursor;

                    if (ccrs->l == 0 || ccrs->cursor == 0)
                        continue;

                    while (nc && ccrs->cmd[nc - 1] == ' ')
                    {
                        nc--;
                        back++;
                    }

                    while (nc && ccrs->cmd[nc - 1] != ' ')
                    {
                        nc--;
                        back++;
                    }
                }
                else /* char */
                {
                    if (ccrs->l == 0 || ccrs->cursor == 0)
                    {
                        write(cli->fd, "\a", 1); // alert (BEL) character
                        continue;
                    }

                    back = 1;
                }

                if (back)
                {
                    while (back--)
                    {
                        if (ccrs->l == ccrs->cursor)
                        {
                            ccrs->cmd[--ccrs->cursor] = 0;
                            if (cli->state != STATE_PASSWORD &&
                                cli->state != STATE_ENABLE_PASSWORD)
                            {
                                write(cli->fd, "\b \b", 3);
                            }
                        }
                        else
                        {
                            int i;
                            ccrs->cursor--;
                            if (cli->state != STATE_PASSWORD &&
                                cli->state != STATE_ENABLE_PASSWORD)
                            {
                                for (i = ccrs->cursor; i <= ccrs->l; i++) {
                                    ccrs->cmd[i] = ccrs->cmd[i+1];
                                }
                                write(cli->fd, "\b", 1);
                                write(cli->fd, ccrs->cmd + ccrs->cursor,
                                      strlen(ccrs->cmd + ccrs->cursor));
                                write(cli->fd, " ", 1);
                                for (i = 0; i <=
                                         (int)strlen(ccrs->cmd + ccrs->cursor);
                                     i++)
                                {
                                    write(cli->fd, "\b", 1);
                                }
                            }
                        }
                        ccrs->l--;
                    }

                    continue;
                }
            }

            /* redraw */
            if (ccrs->c == CTRL('L'))
            {
                int i;
                int cursorback = ccrs->l - ccrs->cursor;

                if (cli->state == STATE_PASSWORD ||
                    cli->state == STATE_ENABLE_PASSWORD)
                {
                    continue;
                }
                write(cli->fd, "\r\n", 2);
                show_prompt(cli, cli->fd);
                write(cli->fd, ccrs->cmd, ccrs->l);

                for (i = 0; i < cursorback; i++)
                    write(cli->fd, "\b", 1);

                continue;
            }

            /* clear line */
            if (ccrs->c == CTRL('U'))
            {
                if (cli->state == STATE_PASSWORD ||
                    cli->state == STATE_ENABLE_PASSWORD)
                {
                    memset(ccrs->cmd, 0, ccrs->l);
                } else {
                    cli_clear_line(cli->fd, ccrs->cmd, ccrs->l, ccrs->cursor);
                }
                ccrs->l = ccrs->cursor = 0;
                continue;
            }

            /* kill to EOL */
            if (ccrs->c == CTRL('K'))
            {
                if (ccrs->cursor == ccrs->l)
                    continue;

                if (cli->state != STATE_PASSWORD &&
                    cli->state != STATE_ENABLE_PASSWORD)
                {
                    int c; // Dangerous, same name, different var...
                    for (c = ccrs->cursor; c < ccrs->l; c++)
                        write(cli->fd, " ", 1);

                    for (c = ccrs->cursor; c < ccrs->l; c++)
                        write(cli->fd, "\b", 1);
                }

                memset(ccrs->cmd + ccrs->cursor, 0, ccrs->l - ccrs->cursor);
                ccrs->l = ccrs->cursor;
                continue;
            }

            /* EOT */
            if (ccrs->c == CTRL('D'))
            {
                if (cli->state == STATE_PASSWORD ||
                    cli->state == STATE_ENABLE_PASSWORD)
                {
                    break;
                }

                if (ccrs->l)
                    continue;

                ccrs->l = -1;
                break;
            }

            /* disable */
            if (ccrs->c == CTRL('Z'))
            {
                if (cli->mode != MODE_EXEC)
                {
                    cli_clear_line(cli->fd, ccrs->cmd, ccrs->l, ccrs->cursor);
                    cli_set_configmode(cli, MODE_EXEC, NULL);
                    cli->showprompt = 1;
                }

                continue;
            }

            /* TAB completion */
            if (ccrs->c == CTRL('I'))
            {
                char *completions[CLI_MAX_LINE_WORDS];
                int num_completions = 0;

                if (cli->state == STATE_LOGIN ||
                    cli->state == STATE_PASSWORD ||
                    cli->state == STATE_ENABLE_PASSWORD)
                {
                    continue;
                }

                if (ccrs->cursor != ccrs->l)
                    continue;

                num_completions =
                    cli_get_completions(cli, ccrs->cmd, completions,
                                        CLI_MAX_LINE_WORDS);
                if (num_completions == 0)
                {
                    write(cli->fd, "\a", 1);
                }
                else if (num_completions == 1)
                {
                    // Single completion
                    for (; ccrs->l > 0; ccrs->l--, ccrs->cursor--)
                    {
                        if (ccrs->cmd[ccrs->l-1] == ' ' ||
                            ccrs->cmd[ccrs->l-1] == '|')
                        {
                            break;
                        }
                        write(cli->fd, "\b", 1);
                    }
                    strcpy((ccrs->cmd + ccrs->l), completions[0]);
                    ccrs->l += strlen(completions[0]);
                    ccrs->cmd[ccrs->l++] = ' ';
                    ccrs->cursor = ccrs->l;
                    write(cli->fd, completions[0], strlen(completions[0]));
                    write(cli->fd, " ", 1);
                }
                else if (ccrs->lastchar == CTRL('I'))
                {
                    // double tab
                    int i;
                    write(cli->fd, "\r\n", 2);
                    for (i = 0; i < num_completions; i++)
                    {
                        write(cli->fd, completions[i],
                              strlen(completions[i]));
                        if (i % 4 == 3)
                            write(cli->fd, "\r\n", 2);
                        else
                            write(cli->fd, "     ", 1);
                    }
                    if (i % 4 != 3) write(cli->fd, "\r\n", 2);
                        cli->showprompt = 1;
                }
                else
                {
                    // More than one completion
                    ccrs->lastchar = ccrs->c;
                    write(cli->fd, "\a", 1);
                }
                continue;
            }

            /* history */
            if (ccrs->c == CTRL('P') || ccrs->c == CTRL('N'))
            {
                int history_found = 0;

                if (cli->state == STATE_LOGIN ||
                    cli->state == STATE_PASSWORD ||
                    cli->state == STATE_ENABLE_PASSWORD)
                {
                    continue;
                }

                if (ccrs->c == CTRL('P')) // Up
                {
                    ccrs->in_history--;
                    if (ccrs->in_history < 0)
                    {
                        for (ccrs->in_history = MAX_HISTORY-1; ccrs->in_history >= 0;
                             ccrs->in_history--)
                        {
                            if (cli->history[ccrs->in_history])
                            {
                                history_found = 1;
                                break;
                            }
                        }
                    }
                    else
                    {
                        if (cli->history[ccrs->in_history]) history_found = 1;
                    }
                }
                else // Down
                {
                    ccrs->in_history++;
                    if (ccrs->in_history >= MAX_HISTORY || !cli->history[ccrs->in_history])
                    {
                        int i = 0;
                        for (i = 0; i < MAX_HISTORY; i++)
                        {
                            if (cli->history[i])
                            {
                                ccrs->in_history = i;
                                history_found = 1;
                                break;
                            }
                        }
                    }
                    else
                    {
                        if (cli->history[ccrs->in_history]) history_found = 1;
                    }
                }
                if (history_found && cli->history[ccrs->in_history])
                {
                    // Show history item
                    cli_clear_line(cli->fd, ccrs->cmd, ccrs->l, ccrs->cursor);
                    memset(ccrs->cmd, 0, CLI_MAX_LINE_LENGTH);
                    strncpy(ccrs->cmd, cli->history[ccrs->in_history], CLI_MAX_LINE_LENGTH - 1);
                    ccrs->l = ccrs->cursor = strlen(ccrs->cmd);
                    write(cli->fd, ccrs->cmd, ccrs->l);
                }

                continue;
            }

            /* left/right cursor motion */
            if (ccrs->c == CTRL('B') || ccrs->c == CTRL('F'))
            {
                if (ccrs->c == CTRL('B')) /* Left */
                {
                    if (ccrs->cursor)
                    {
                        if (cli->state != STATE_PASSWORD && cli->state != STATE_ENABLE_PASSWORD)
                            write(cli->fd, "\b", 1);

                        ccrs->cursor--;
                    }
                }
                else /* Right */
                {
                    if (ccrs->cursor < ccrs->l)
                    {
                        if (cli->state != STATE_PASSWORD && cli->state != STATE_ENABLE_PASSWORD)
                            write(cli->fd, &ccrs->cmd[ccrs->cursor], 1);

                        ccrs->cursor++;
                    }
                }

                continue;
            }

            /* start of line */
            if (ccrs->c == CTRL('A'))
            {
                if (ccrs->cursor)
                {
                    if (cli->state != STATE_PASSWORD && cli->state != STATE_ENABLE_PASSWORD)
                    {
                        write(cli->fd, "\r", 1);
                        show_prompt(cli, cli->fd);
                    }

                    ccrs->cursor = 0;
                }

                continue;
            }

            /* end of line */
            if (ccrs->c == CTRL('E'))
            {
                if (ccrs->cursor < ccrs->l)
                {
                    if (cli->state != STATE_PASSWORD && cli->state != STATE_ENABLE_PASSWORD)
                        write(cli->fd, &ccrs->cmd[ccrs->cursor], ccrs->l - ccrs->cursor);

                    ccrs->cursor = ccrs->l;
                }

                continue;
            }

            /* normal character typed */
            if (ccrs->cursor == ccrs->l)
            {
                 /* append to end of line */
                ccrs->cmd[ccrs->cursor] = ccrs->c;
                if (ccrs->l < CLI_MAX_LINE_LENGTH - 1)
                {
                    ccrs->l++;
                    ccrs->cursor++;
                }
                else
                {
                    write(cli->fd, "\a", 1);
                    continue;
                }
            }
            else
            {
                // Middle of text
                if (ccrs->insertmode)
                {
                    int i;
                    // Move everything one character to the right
                    if (ccrs->l >= CLI_MAX_LINE_LENGTH - 2) ccrs->l--;
                    for (i = ccrs->l; i >= ccrs->cursor; i--)
                        ccrs->cmd[i + 1] = ccrs->cmd[i];
                    // Write what we've just added
                    ccrs->cmd[ccrs->cursor] = ccrs->c;

                    write(cli->fd, &ccrs->cmd[ccrs->cursor], ccrs->l - ccrs->cursor + 1);
                    for (i = 0; i < (ccrs->l - ccrs->cursor + 1); i++)
                        write(cli->fd, "\b", 1);
                    ccrs->l++;
                }
                else
                {
                    ccrs->cmd[ccrs->cursor] = ccrs->c;
                }
                ccrs->cursor++;
            }

            if (cli->state != STATE_PASSWORD && cli->state != STATE_ENABLE_PASSWORD)
            {
                if (ccrs->c == '?' && ccrs->cursor == ccrs->l)
                {
                    write(cli->fd, "\r\n", 2);
                    ccrs->oldcmd = ccrs->cmd;
                    ccrs->oldl = ccrs->cursor = ccrs->l - 1;
                    break;
                }
                write(cli->fd, &ccrs->c, 1);
            }

            ccrs->oldcmd = 0;
            ccrs->oldl = 0;
            ccrs->lastchar = ccrs->c;
        } // End of inner while(1) loop

        if (ccrs->l < 0) break;

        if (cli->state == STATE_LOGIN)
        {
            if (ccrs->l == 0) continue;

            /* require login */
            free_z(ccrs->username);
            if (!(ccrs->username = strdup(ccrs->cmd))) {
                retval = CLI_QUIT;
                goto CCR_FINISH;
            }
            cli->state = STATE_PASSWORD;
            cli->showprompt = 1;
        }
        else if (cli->state == STATE_PASSWORD)
        {
            /* require password */
            int allowed = 0;

            free_z(ccrs->password);
            if (!(ccrs->password = strdup(ccrs->cmd))) {
                  ccrReturn(CLI_QUIT);
            }
            if (cli->auth_callback)
            {
                if (cli->auth_callback(ccrs->username, ccrs->password) == CLI_OK)
                    allowed++;
            }

            if (!allowed)
            {
                struct unp *u;
                for (u = cli->users; u; u = u->next)
                {
                    if (!strcmp(u->username, ccrs->username) &&
                        pass_matches(u->password, ccrs->password))
                    {
                        allowed++;
                        break;
                    }
                }
            }

            if (allowed)
            {
                cli_error(cli, "%s", "");
                cli->state = STATE_NORMAL;
            }
            else
            {
                cli_error(cli, "\n\nAccess denied");
                free_z(ccrs->username);
                free_z(ccrs->password);
                cli->state = STATE_LOGIN;
            }

            cli->showprompt = 1;
        }
        else if (cli->state == STATE_ENABLE_PASSWORD)
        {
            int allowed = 0;
            if (cli->enable_password)
            {
                /* check stored static enable password */
                if (pass_matches(cli->enable_password, ccrs->cmd))
                    allowed++;
            }

            if (!allowed && cli->enable_callback)
            {
                /* check callback */
                if (cli->enable_callback(ccrs->cmd))
                    allowed++;
            }

            if (allowed)
            {
                cli->state = STATE_ENABLE;
                cli_set_privilege(cli, PRIVILEGE_PRIVILEGED);
            }
            else
            {
                cli_error(cli, "\n\nAccess denied");
                cli->state = STATE_NORMAL;
            }
        }
        else
        {
            if (ccrs->l == 0) continue;
            if (ccrs->cmd[ccrs->l - 1] != '?' &&
                strcasecmp(ccrs->cmd, "history") != 0)
            {
                retval = cli_add_history(cli, ccrs->cmd);
                if (retval != CLI_OK) {
                    break;
                }
            }
            if (cli_run_command(cli, ccrs->cmd) == CLI_QUIT) {
                fprintf(stderr, "cli_run_command() returned CLI_QUIT\n");
                retval = CLI_QUIT;
                break;
            }
        }

        // Update the last_action time now as the last command run could take a
        // long time to return
        if (cli->idle_timeout)
            time(&cli->last_action);
    } // End of outer while(1) loop

    cli_free_history(cli);
    free_z(ccrs->username);
    free_z(ccrs->password);
    free_z(ccrs->cmd);

    fclose(cli->client);
    cli->client = 0;
    if (retval == CLI_UNINITIALIZED) {
        fprintf(stderr, "Got to end of cli processing, "
               "retval was CLI_UNINITIALIZED...\n");
        retval = CLI_QUIT;
    }

CCR_FINISH:
    assert(retval != CLI_UNINITIALIZED);
    ccrFinishDontFreeCcrParam(retval); // ccr param and sub-mallocs freed elsewhere.
}
#endif // CLI_NB_ST

int cli_file(struct cli_def *cli, FILE *fh, int privilege, int mode)
{
    int oldpriv = cli_set_privilege(cli, privilege);
    int oldmode = cli_set_configmode(cli, mode, NULL);
    char buf[CLI_MAX_LINE_LENGTH];

    while (1)
    {
        char *p;
        char *cmd;
        char *end;

        if (fgets(buf, CLI_MAX_LINE_LENGTH - 1, fh) == NULL)
            break; /* end of file */

        if ((p = strpbrk(buf, "#\r\n")))
            *p = 0;

        cmd = buf;
        while (isspace(*cmd))
            cmd++;

        if (!*cmd)
            continue;

        for (p = end = cmd; *p; p++)
            if (!isspace(*p))
                end = p;

        *++end = 0;
        if (strcasecmp(cmd, "quit") == 0)
            break;

        if (cli_run_command(cli, cmd) == CLI_QUIT)
            break;
    }

    cli_set_privilege(cli, oldpriv);
    cli_set_configmode(cli, oldmode, NULL /* didn't save desc */);

    return CLI_OK;
}

static void _print(struct cli_def *cli, int print_mode, char *format, va_list ap)
{
    va_list aq;
    int n;
    char *p;

    if (!cli) return; // sanity check

    while (1)
    {
        va_copy(aq, ap);
        n = vsnprintf(cli->buffer, cli->buf_size, format, ap);
        if (n >= cli->buf_size)
        {
            cli->buf_size = n + 1;
            cli->buffer = realloc(cli->buffer, cli->buf_size);
            if (!cli->buffer)
                return;
            va_end(ap);
            va_copy(ap, aq);
            continue;
        }
        break;
    }

    if (n < 0) // vsnprintf failed
        return;

    p = cli->buffer;

    size_t slen = strlen(p);

    do
    {
        char *next = strchr(p, '\n');
        struct cli_filter *f = (print_mode & PRINT_FILTERED) ? cli->filters : 0;
        int print = 1;

        if (next)
            *next++ = 0;
        else if (print_mode & PRINT_BUFFERED)
            break;

        while (print && f)
        {
            print = (f->filter(cli, p, f->data) == CLI_OK);
            f = f->next;
        }
        if (print)
        {
            if (cli->print_callback)
                cli->print_callback(cli, p);
            else if (cli->client)
                fprintf(cli->client, "%s\r\n", p);
        }

        p = next;
    } while (p && (p < cli->buffer + slen));

    if (p && *p)
    {
        if (p != cli->buffer)
        memmove(cli->buffer, p, strlen(p));
    }
    else *cli->buffer = 0;
}

void cli_bufprint(struct cli_def *cli, char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    _print(cli, PRINT_BUFFERED|PRINT_FILTERED, format, ap);
    va_end(ap);
}

void cli_vabufprint(struct cli_def *cli, char *format, va_list ap)
{
    _print(cli, PRINT_BUFFERED, format, ap);
}

void cli_print(struct cli_def *cli, char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    _print(cli, PRINT_FILTERED, format, ap);
    va_end(ap);
}

void cli_error(struct cli_def *cli, char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    _print(cli, PRINT_PLAIN, format, ap);
    va_end(ap);
}

struct cli_match_filter_state
{
    int flags;
#define MATCH_REGEX                1
#define MATCH_INVERT                2
    union {
        char *string;
        regex_t re;
    } match;
};

int cli_match_filter_init(struct cli_def *cli, int argc, char **argv, struct cli_filter *filt)
{
    struct cli_match_filter_state *state;
    int rflags;
    int i;
    char *p;

    if (argc < 2)
    {
        if (cli->client)
            fprintf(cli->client, "Match filter requires an argument\r\n");

        return CLI_ERROR;
    }

    filt->filter = cli_match_filter;
    filt->data = state = calloc(sizeof(struct cli_match_filter_state), 1);

    if (argv[0][0] == 'i' || // include/exclude
        (argv[0][0] == 'e' && argv[0][1] == 'x'))
    {
        if (argv[0][0] == 'e')
            state->flags = MATCH_INVERT;

        state->match.string = join_words(argc-1, argv+1);
        return CLI_OK;
    }

#ifdef WIN32
    /*
     * No regex functions in windows, so return an error
     */
    return CLI_ERROR;
#endif

    state->flags = MATCH_REGEX;

    // grep/egrep
    rflags = REG_NOSUB;
    if (argv[0][0] == 'e') // egrep
        rflags |= REG_EXTENDED;

    i = 1;
    while (i < argc - 1 && argv[i][0] == '-' && argv[i][1])
    {
        int last = 0;
        p = &argv[i][1];

        if (strspn(p, "vie") != strlen(p))
            break;

        while (*p)
        {
            switch (*p++)
            {
                case 'v':
                    state->flags |= MATCH_INVERT;
                    break;

                case 'i':
                    rflags |= REG_ICASE;
                    break;

                case 'e':
                    last++;
                    break;
            }
        }

        i++;
        if (last)
            break;
    }

    p = join_words(argc-i, argv+i);
    if ((i = regcomp(&state->match.re, p, rflags)))
    {
        if (cli->client)
            fprintf(cli->client, "Invalid pattern \"%s\"\r\n", p);

        free_z(p);
        return CLI_ERROR;
    }

    free_z(p);
    return CLI_OK;
}

int cli_match_filter(UNUSED(struct cli_def *cli), char *string, void *data)
{
    struct cli_match_filter_state *state = data;
    int r = CLI_ERROR;

    if (!string) // clean up
    {
        if (state->flags & MATCH_REGEX)
            regfree(&state->match.re);
        else
            free(state->match.string);

        free(state);
        return CLI_OK;
    }

    if (state->flags & MATCH_REGEX)
    {
        if (!regexec(&state->match.re, string, 0, NULL, 0))
            r = CLI_OK;
    }
    else
    {
        if (strstr(string, state->match.string))
            r = CLI_OK;
    }

    if (state->flags & MATCH_INVERT)
    {
        if (r == CLI_OK)
            r = CLI_ERROR;
        else
            r = CLI_OK;
    }

    return r;
}

struct cli_range_filter_state {
    int matched;
    char *from;
    char *to;
};

int cli_range_filter_init(struct cli_def *cli, int argc, char **argv, struct cli_filter *filt)
{
    struct cli_range_filter_state *state;
    char *from = 0;
    char *to = 0;

    if (!strncmp(argv[0], "bet", 3)) // between
    {
        if (argc < 3)
        {
            if (cli->client)
                fprintf(cli->client, "Between filter requires 2 arguments\r\n");

            return CLI_ERROR;
        }

        if (!(from = strdup(argv[1])))
            return CLI_ERROR;
        to = join_words(argc-2, argv+2);
    }
    else // begin
    {
        if (argc < 2)
        {
            if (cli->client)
                fprintf(cli->client, "Begin filter requires an argument\r\n");

            return CLI_ERROR;
        }

        from = join_words(argc-1, argv+1);
    }

    filt->filter = cli_range_filter;
    filt->data = state = calloc(sizeof(struct cli_range_filter_state), 1);

    state->from = from;
    state->to = to;

    return CLI_OK;
}

int cli_range_filter(UNUSED(struct cli_def *cli), char *string, void *data)
{
    struct cli_range_filter_state *state = data;
    int r = CLI_ERROR;

    if (!string) // clean up
    {
        free_z(state->from);
        free_z(state->to);
        free_z(state);
        return CLI_OK;
    }

    if (!state->matched)
    state->matched = !!strstr(string, state->from);

    if (state->matched)
    {
        r = CLI_OK;
        if (state->to && strstr(string, state->to))
            state->matched = 0;
    }

    return r;
}

int cli_count_filter_init(struct cli_def *cli, int argc, UNUSED(char **argv), struct cli_filter *filt)
{
    if (argc > 1)
    {
        if (cli->client)
            fprintf(cli->client, "Count filter does not take arguments\r\n");

        return CLI_ERROR;
    }

    filt->filter = cli_count_filter;
    if (!(filt->data = calloc(sizeof(int), 1)))
        return CLI_ERROR;

    return CLI_OK;
}

int cli_count_filter(struct cli_def *cli, char *string, void *data)
{
    int *count = data;

    if (!string) // clean up
    {
        // print count
        if (cli->client)
            fprintf(cli->client, "%d\r\n", *count);

        free(count);
        return CLI_OK;
    }

    while (isspace(*string))
        string++;

    if (*string)
        (*count)++;  // only count non-blank lines

    return CLI_ERROR; // no output
}

void cli_print_callback(struct cli_def *cli, void (*callback)(struct cli_def *, char *))
{
    cli->print_callback = callback;
}

void cli_set_idle_timeout(struct cli_def *cli, unsigned int seconds)
{
    if (seconds < 1) seconds = 0;
    cli->idle_timeout = seconds;
    time(&cli->last_action);
}

void cli_set_idle_timeout_callback(struct cli_def *cli, unsigned int seconds, int (*callback)(struct cli_def *))
{
    cli_set_idle_timeout(cli, seconds);
    cli->idle_timeout_callback = callback;
}
