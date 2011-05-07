#ifndef _LIBCLI_H_
#define _LIBCLI_H_

#define CLI_NB_ST 1
#include "libcli.h"

#ifdef __GNUC__
# define UNUSED(d) d __attribute__ ((unused))
#else
# define UNUSED(d) d
#endif


#define CLI2_DEFAULT_PORT    "25190"

struct Cli {
    struct sock_ev_serv *server;
    struct ev_timer init_timer;
    char *addr_str;
    char *port_str;
    int n_clients;
};

struct CliCmdSpec {
    char *command;
    int (*callback)(struct cli_def *, char *, char **, int);
    char *help;
    int privilege;
    int mode;
    int child;
};

struct Cli* cliwrap_init(
    struct ev_loop *evloop,
    const char *addr_str,
    const char *port_str,
    int n_clients,
    void *udata);

void cliwrap_cleanup(EV_P_ struct Cli **cli);

/* Is implemented by every agent that uses cli in cli_cmd.c respectively */
struct CliCmdSpec *cli_get_commands(void);

/* Impement in cli_cmd.c, the fcn can return NULL if you want the default
   banner  */
const char *cli_get_banner(void);

/* Impement in cli_cmd.c, the fcn can return NULL if you want the default
   hostname  */
const char *cli_get_hostname(void);

#endif
