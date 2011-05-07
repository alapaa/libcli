#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <errno.h>
#include <fcntl.h>
#include <ev.h>
#include <assert.h>

#include "coroutine.h"

#include "elog.h"
#include "iputils.h"

#include "libcli_wrapper.h"

#define MODE_CONFIG_INT             10

#ifdef __GNUC__
# define UNUSED(d) d __attribute__ ((unused))
#else
# define UNUSED(d) d
#endif

struct sock_ev_serv {
    ev_io io;
    ev_signal signal_watcher;
    int fd;
    int socket_len;

    struct sock_ev_client *client_list;
    size_t n_clients;
    void *udata;
};

struct sock_ev_client {
    ev_io io;
    int index;
    struct sock_ev_serv* server;

    struct cli_def *cli;
    struct sock_ev_client *prev;
    struct sock_ev_client *next;
};

unsigned int regular_count = 0;
unsigned int debug_regular = 0;

static int setup_cli(struct sock_ev_client *client, struct sock_ev_serv *server);
static int setnonblock(int fd);

static void client_cb(EV_P_ ev_io *w, int revents);

static struct sock_ev_client* client_new(int fd, struct sock_ev_serv *server)
{
    struct sock_ev_client *client  = calloc(1, sizeof(struct sock_ev_client));

    int result = setup_cli(client, server);
    if (result < 0 || !client->cli) {
        ERR("CLI setup failed");
        exit(EXIT_FAILURE);
    }

    client->cli->fd = fd;
    client->cli->z = 0; /* Re-entrant coroutine state struct */
    client->cli->revents = 0;

    setnonblock(client->cli->fd);
    ev_io_init(&client->io, client_cb, client->cli->fd, EV_READ|EV_WRITE);

    return client;
}

static void client_del(UNUSED(EV_P_ ev_io *w), struct sock_ev_client **client)
{
    D("Entered %s", __FUNCTION__);

    assert(client);
    assert(*client); /* Free of NULL is nominally OK, but we want to detect it */
    ev_io_stop(EV_A_ &(*client)->io);
    close((*client)->cli->fd);
    cli_done((*client)->cli);
    free(*client);
    *client = NULL; /* For error detection */
}


/* Add a client at head of list */
static void clilist_add_front( struct sock_ev_serv *server,
                                 struct sock_ev_client *client)
{
    /* Add new client at front */
    if (server->client_list) {
        server->client_list->prev = client;
    }
    client->next = server->client_list;
    server->client_list = client;
    server->n_clients++;
}

/* Remove client from list */
static void clilist_del( struct sock_ev_client *client)
{
    /* Unlink */
    if (client->prev) {
        client->prev->next = client->next;
    }

    if (client->next) {
        client->next->prev = client->prev;
    }

    client->server->n_clients--;
    if (client == client->server->client_list) {
        client->server->client_list = client->server->client_list->next;
    }
    assert(client->server->n_clients >= 0);
}


static void clilist_cleanup_all(
    EV_P_ ev_io *w,
    struct sock_ev_serv *server)
{
    D("Entered %s. n_clients: %d\n", __FUNCTION__, server->n_clients);

    struct sock_ev_client *curr = server->client_list;
    struct sock_ev_client *next = NULL;
    while(curr) {
        next = curr->next;
        client_del(EV_A_ w, &curr);
        server->n_clients--;
        curr = next;
    }

    server->client_list = NULL;

    assert(server->n_clients == 0);
}


/* This callback is called when client data is available */
static void client_cb( EV_P_ ev_io *w, int revents)
{
    /* a client has become readable or writable */
    int retval = CLI_UNINITIALIZED;

    /* The io listener is first in struct, so cast below is OK. */
    struct sock_ev_client* client = (struct sock_ev_client*) w;
    client->cli->revents = revents;

    /* if (revents & EV_WRITE) { */
    /*     printf("w%d", client->cli->fd); */
    /* } */
    /* if (revents & EV_READ) { */
    /*     printf("R%d", client->cli->fd); */
    /* } */
    if ( (revents & EV_READ)==0 &&
         client->cli->callback_only_on_fd_readable == 1)
    {
        D("\nError! Requested callbacks only when fd readable, got "
          "callback without fd readable\n\n");
    }
    /* printf(".  "); */
    /* fflush(stdout); */

    retval = cli_process_event(client->cli);

    if (retval != CLI_OK) {
        /* Do cleanup */
        clilist_del(client);
        client_del(EV_A_ &client->io, &client);
    } else {
        if (client->cli->callback_only_on_fd_readable == 1 &&
            (client->cli->wanted_revents & EV_WRITE) )
        {
            ev_io_stop(EV_A_ &client->io);
            ev_io_set(&client->io, client->cli->fd, EV_READ);
            client->cli->wanted_revents = EV_READ;
            /* printf("Only read events enabled on sock %d...\n", client->cli->fd); */
            ev_io_start(EV_A_ &client->io);
        } else if (client->cli->callback_only_on_fd_readable == 0 &&
                   (client->cli->wanted_revents & EV_WRITE) == 0)
        {
            ev_io_stop(EV_A_ &client->io);
            ev_io_set(&client->io, client->cli->fd, EV_READ|EV_WRITE);
            client->cli->wanted_revents = EV_READ|EV_WRITE;
            /* printf("    Both read AND write events enabled on sock %d\n", */
            /* client->cli->fd); */
            ev_io_start(EV_A_ &client->io);
        }
    }
}

/* This callback is called when data is readable on the socket. */
static void server_cb( EV_P_ ev_io *w, UNUSED(int revents))
{
    int client_fd;
    struct sock_ev_client* client;
    struct sockaddr_storage remote_addr;
    socklen_t len;
    char ipstr[INET6_ADDRSTRLEN];
    int port;

    /* since ev_io is the first member, */
    /* watcher `w` has the address of the */
    /* start of the sock_ev_serv struct */
    struct sock_ev_serv* server = (struct sock_ev_serv*) w;

    while (1)
    {
        client_fd = accept(server->fd, NULL, NULL);
        if( client_fd == -1 )
        {
            if( errno != EAGAIN && errno != EWOULDBLOCK )
            {
                ERR("CLI accept() failed errno=%i (%s)",  errno, strerror(errno));
                exit(EXIT_FAILURE);
            }
            break;
        }

        len = sizeof(remote_addr);
        getpeername(client_fd, (struct sockaddr*)&remote_addr, &len);

        // deal with both IPv4 and IPv6:
        if (remote_addr.ss_family == AF_INET) {
            struct sockaddr_in *s = (struct sockaddr_in *)&remote_addr;
            port = ntohs(s->sin_port);
            inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof ipstr);
        } else { // AF_INET6
            struct sockaddr_in6 *s = (struct sockaddr_in6 *)&remote_addr;
            port = ntohs(s->sin6_port);
            inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof ipstr);
        }

        INFO("Accepted CLI connection; Peer IP address: %s, peer port: %d\n",
             ipstr, port);

        client = client_new(client_fd, server);
        clilist_add_front(server, client);

        ev_io_start(EV_A_ &client->io);
    }
}

/* Simply adds O_NONBLOCK to the file descriptor of choice */
static int setnonblock(int fd)
{
    int flags;

    flags = fcntl(fd, F_GETFL);
    flags |= O_NONBLOCK;
    return fcntl(fd, F_SETFL, flags);
}

/* Remember to do freeaddrinfo on *ai in caller! */
static int socket_init(
    /* struct sockaddr_storage *ss, */
    UNUSED(int max_queue),
    const char *addr_str,
    const char *port_str,
    struct addrinfo **ai)
{
    int fd;
    int on = 1;
    *ai = NULL;

    struct addrinfo hints;
    struct addrinfo* servinfo;
    int retval;

    memset(&hints,0,sizeof(hints));

    if (strchr(addr_str, ':') == 0) {
        hints.ai_family=AF_INET;
    } else {
        hints.ai_family=AF_INET6;
    }
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if ( (retval = getaddrinfo(addr_str, port_str, &hints, &servinfo)) != 0 ) {
        ERR("Failed to get listening address ([%s]:%s): %s",
             addr_str, port_str, gai_strerror(retval));
        return 0;
    }

    if ((fd = socket(servinfo->ai_family, servinfo->ai_socktype,
                     servinfo->ai_protocol)) == -1)
    {
        ERR("Failed to create socket'%s:%s' : %s", addr_str, port_str,
            strerror(errno));
        freeaddrinfo(servinfo);
        errno = 0;
        return 0;
    }

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    /* Set it non-blocking */
    if (setnonblock(fd) == -1) {
        ERR("Could not set CLI to non-blocking.");
        exit(EXIT_FAILURE);
    }

    *ai = servinfo; /* Caller must do freeaddrinfo() */
    return fd;
}

static int server_init(struct sock_ev_serv* server, int max_queue,
                       const char *addr_str, const char *port_str)
{
    struct addrinfo *servinfo;
    server->fd = socket_init(max_queue, addr_str, port_str, &servinfo);

    if (bind(server->fd, servinfo->ai_addr, servinfo->ai_addrlen) == -1)
    {
      ERR("Could not bind the CLI.");
      freeaddrinfo(servinfo);
      return -1;
    }

    if (listen(server->fd, max_queue) == -1) {
        ERR("Could not listen on CLI port: %s", port_str);
      freeaddrinfo(servinfo);
      return -1;
    }

    D("Listening on port %s\n", port_str);

    freeaddrinfo(servinfo);

    return 0;
}

void cliwrap_cleanup(EV_P_ struct Cli **cli)
{
    D("Closing server fd");
    close((*cli)->server->fd);
    D("Cleaning up all remaining clients");
    clilist_cleanup_all(EV_A_ &((*cli)->server)->io, (*cli)->server);
    D("Stopping init_timer");
    ev_timer_stop(EV_A_ &(*cli)->init_timer);

    free((*cli)->addr_str);
    free((*cli)->port_str);
    free((*cli)->server);
    free(*cli);
    *cli = NULL;
}

#if 0
static int check_auth(char *username, char *password)
{
    if (strcasecmp(username, "root") != 0)
        return CLI_ERROR;

    if (strcasecmp(password, "") != 0)
        return CLI_ERROR;
    return CLI_OK;
}
#endif

static int check_enable(char *password)
{
    return !strcasecmp(password, "topsecret");
}

static int register_commands(struct cli_def *cli)
{
    struct CliCmdSpec *curr = cli_get_commands();
    /* TODO: Where to place this? */

    struct cli_command *result = NULL;

    while (curr->command) {
        struct cli_command *parent;
        // Note that we use the cli_register_command_sargc() variant below to
        // get std argc, since "vanilla" libcli has argc that does not count
        // command name.
        result = cli_register_command_sargc(
            cli, curr->child?parent:NULL, curr->command, curr->callback,
            curr->privilege != 0 ? curr->privilege : PRIVILEGE_UNPRIVILEGED,
            curr->mode != 0 ? curr->mode : MODE_EXEC,
            curr->help);

        if (!result) {
            return -1;
        }

        if (!curr->child) {
            parent = result;
        }

        curr++;
    }

    return 0;
}

static int setup_cli(struct sock_ev_client *client, struct sock_ev_serv *server)
{
    int retval = 0;

    client->cli = cli_init();
    assert(client->cli);
    client->server = server;
    client->cli->udata = client->server->udata;

    const char *default_banner =
        "UsersGuide:\n" \
        "http://code.google.com/p/libcli/wiki/UsersGuide\n"
        "Type ? for help or q to quit.\n";

    const char *user_def_banner = cli_get_banner();
    const char *banner = NULL;

    if (user_def_banner) {
        banner = user_def_banner;
    } else {
        banner = default_banner;
    }
    cli_set_banner(client->cli, banner);

    const char *default_hostname = "router";
    const char *user_def_hostname = cli_get_hostname();
    const char *hostname;
    if (user_def_hostname) {
        hostname = user_def_hostname;
    } else {
        hostname = default_hostname;
    }
    cli_set_hostname(client->cli, hostname);

    /* cli_set_auth_callback(client->cli, check_auth); */
    cli_set_enable_callback(client->cli, check_enable);

    retval = register_commands(client->cli);

    if (retval == -1) {
        exit(EXIT_FAILURE);
    }

    return 0;
}

static void init_cb(EV_P_ ev_timer *w, UNUSED(int revents))
{
    struct Cli *cli = (struct Cli *)w->data;
    if (server_init(cli->server, cli->n_clients, cli->addr_str, cli->port_str) != 0) {
        INFO("Could not init the cli. Trying again in %f seconds.", w->repeat);
        ev_timer_again(loop, w);
        return;
    }

    ev_timer_stop(loop, w);

    ev_io_init(&cli->server->io, server_cb, cli->server->fd, EV_READ);
    ev_io_start(EV_A_ &cli->server->io);

    INFO("CLI is up and running.");
}

struct Cli* cliwrap_init(EV_P_ const char *addr_str, const char *port_str,
                          int n_clients, void *udata)
{
    D("Entered %s\n", __FUNCTION__);
    struct Cli* cli = calloc(1, sizeof(struct Cli));

    cli->server = calloc(1, sizeof(struct sock_ev_serv));
    cli->server->udata = udata;
    cli->port_str = strndup(port_str, 5);
    cli->addr_str = strndup(addr_str, 64);
    cli->n_clients = n_clients;

    ev_timer_init(&cli->init_timer, &init_cb, 0.0, 30.0);
    cli->init_timer.data = cli;
    ev_timer_start(loop, &cli->init_timer);

    D("Finished cliwrap_init()");

    return cli;

}
