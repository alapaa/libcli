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

#include "libcli.h"

// Includes from unix echo server code
#include <errno.h>
#include <fcntl.h>

#include <sys/un.h>

#include <ev.h>
#include <assert.h>


#include "coroutine.h"

// End includes from unix echo server code

#define CLITEST_PORT                8000
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
    struct sockaddr_in addr;
    int socket_len;

    struct sock_ev_client *client_list;
    size_t n_clients;
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

int setup_cli(struct cli_def **cli_def);
int setnonblock(int fd);
static void not_blocked(EV_P_ ev_periodic *w, int revents);
static void client_cb(EV_P_ ev_io *w, int revents);

static struct sock_ev_client* client_new(
    int fd,
    struct sock_ev_serv *server)
{
    struct sock_ev_client *client  = calloc(1, sizeof(struct sock_ev_client));

    int result = setup_cli(&client->cli);
    if (result < 0 || !client->cli) {
        perror("CLI setup failed");
        exit(EXIT_FAILURE);
    }

    client->cli->fd = fd;
    client->cli->z = 0; // Re-entrant coroutine state struct
    client->cli->revents = 0;

    client->server = server;
    setnonblock(client->cli->fd);
    ev_io_init(&client->io, client_cb, client->cli->fd, EV_READ|EV_WRITE);

    return client;
}

static void client_del(
    EV_P_ ev_io *w,
    struct sock_ev_client **client)
{
    assert(client);
    assert(*client); // Free of NULL is nominally OK, but we want to detect it
    printf("Doing cleanup, client addr %p\n", *client);
    ev_io_stop(EV_A_ &(*client)->io);
    close((*client)->cli->fd);
    cli_done((*client)->cli);
    free(*client);
    *client = NULL; // For error detection
}


// Add a client at head of list
void list_add_front(
    struct sock_ev_serv *server,
    struct sock_ev_client *client)
{
    // Add new client at front
    if (server->client_list) {
        server->client_list->prev = client;
    }
    client->next = server->client_list;
    server->client_list = client;
    server->n_clients++;
}

// Remove client from list
void list_del(
    struct sock_ev_client *client)
{
    // Unlink
    if (client->prev) {
        if (client->next) {
            client->next->prev = client->prev;
        }
    }

    if (client->next) {
        if (client->prev) {
            client->prev->next = client->next;
        }
    }

    client->server->n_clients--;
    if (client == client->server->client_list) {
        client->server->client_list = client->server->client_list->next;
    }
    assert(client->server->n_clients >= 0);
}


void list_cleanup_all(
    EV_P_ ev_io *w,
    struct sock_ev_serv *server)
{
    printf("Entered list_cleanup_all()\n");

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


// This callback is called when client data is available
static void client_cb(
    EV_P_ ev_io *w,
    int revents)
{
    // a client has become readable or writable
    int retval = CLI_UNINITIALIZED;

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
        printf("\nError! Requested callbacks only when fd readable, got "
               "callback without fd readable\n\n");
    }
    /* printf(".  "); */
    /* fflush(stdout); */

    retval = cli_process_event(client->cli);

    if (retval != CLI_OK) {
        // Do cleanup
        list_del(client);
        client_del(EV_A_ &client->io, &client);
    } else {
        if (client->cli->callback_only_on_fd_readable == 1 &&
            (client->cli->wanted_revents & EV_WRITE) )
        {
            ev_io_stop(EV_A_ &client->io);
            ev_io_set(&client->io, client->cli->fd, EV_READ);
            client->cli->wanted_revents = EV_READ;
            //printf("Only read events enabled on sock %d...\n", client->cli->fd);
            ev_io_start(EV_A_ &client->io);
        } else if (client->cli->callback_only_on_fd_readable == 0 &&
                   (client->cli->wanted_revents & EV_WRITE) == 0)
        {
            ev_io_stop(EV_A_ &client->io);
            ev_io_set(&client->io, client->cli->fd, EV_READ|EV_WRITE);
            client->cli->wanted_revents = EV_READ|EV_WRITE;
            //printf("    Both read AND write events enabled on sock %d\n",
            // client->cli->fd);
            ev_io_start(EV_A_ &client->io);
        }
    }
}

// This callback is called when data is readable on the unix socket.
static void server_cb(
    EV_P_ ev_io *w,
    int revents)
{
    puts("socket has become readable");

    int client_fd;
    struct sock_ev_client* client;

    // since ev_io is the first member,
    // watcher `w` has the address of the
    // start of the sock_ev_serv struct
    struct sock_ev_serv* server = (struct sock_ev_serv*) w;

    while (1)
    {
        client_fd = accept(server->fd, NULL, NULL);
        if( client_fd == -1 )
        {
            if( errno != EAGAIN && errno != EWOULDBLOCK )
            {
                printf("accept() failed errno=%i (%s)",  errno, strerror(errno));
                exit(EXIT_FAILURE);
            }
            break;
        }
        struct sockaddr_in remote_addr;
        socklen_t len = sizeof(remote_addr);
        if (getpeername(client_fd, (struct sockaddr *)&remote_addr, &len)
            >= 0)
        {
            printf(" * accepted connection from %s\n",
                   inet_ntoa(remote_addr.sin_addr));
        }

        client = client_new(client_fd, server);
        list_add_front(server, client);

        ev_io_start(EV_A_ &client->io);
    }
}

// Simply adds O_NONBLOCK to the file descriptor of choice
int setnonblock(
    int fd)
{
    int flags;

    flags = fcntl(fd, F_GETFL);
    flags |= O_NONBLOCK;
    return fcntl(fd, F_SETFL, flags);
}

int socket_init(
    struct sockaddr_in* addr,
    int max_queue)
{
    int fd;
    int on = 1;

    // Setup a socket listener.

    if ((fd = socket(addr->sin_family, SOCK_STREAM, 0)) < 0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));


    // Set it non-blocking
    if (-1 == setnonblock(fd)) {
        perror("echo server socket nonblock");
        exit(EXIT_FAILURE);
    }

   return fd;
}

int server_init(
    struct sock_ev_serv* server,
    int max_queue)
{
    server->fd = socket_init(&server->addr, max_queue);
    //server->socket_len = sizeof(server->socket.sun_family) +
    // strlen(server->socket.sun_path);
    server->socket_len = sizeof(server->addr);

    if (-1 == bind(server->fd, (struct sockaddr*) &server->addr, server->socket_len))
    {
      perror("echo server bind");
      exit(EXIT_FAILURE);
    }

    if (-1 == listen(server->fd, max_queue)) {
      perror("listen");
      exit(EXIT_FAILURE);
    }

    printf("Listening on port %d\n", CLITEST_PORT);
    return 0;
}

static void
sigint_cb (
    EV_P_ ev_signal *w,
    int revents)
{
    printf("\nGot signal %d\n", w->signum);

    ev_unloop (EV_A_ EVUNLOOP_ALL);
}

static void not_blocked(
    EV_P_ ev_periodic *w,
    int revents)
{
    //puts("...\n");
}

int cmd_test(
    struct cli_def *cli,
    char *command,
    char *argv[],
    int argc)
{
    int i;
    cli_print(cli, "called %s with \"%s\"", __FUNCTION__, command);
    cli_print(cli, "%d arguments:", argc);
    for (i = 0; i < argc; i++)
        cli_print(cli, "        %s", argv[i]);

    return CLI_OK;
}

int cmd_set(
    struct cli_def *cli,
    UNUSED(char *command),
    char *argv[],
    int argc)
{
    if (argc < 2 || strcmp(argv[0], "?") == 0)
    {
        cli_print(cli, "Specify a variable to set");
        return CLI_OK;
    }

    if (strcmp(argv[1], "?") == 0)
    {
        cli_print(cli, "Specify a value");
        return CLI_OK;
    }

    if (strcmp(argv[0], "regular_interval") == 0)
    {
        unsigned int sec = 0;
        if (!argv[1] && !&argv[1])
        {
            cli_print(cli, "Specify a regular callback interval in seconds");
            return CLI_OK;
        }
        sscanf(argv[1], "%d", &sec);
        if (sec < 1)
        {
            cli_print(cli, "Specify a regular callback interval in seconds");
            return CLI_OK;
        }
        cli->timeout_tm.tv_sec = sec;
        cli->timeout_tm.tv_usec = 0;
        cli_print(cli, "Regular callback interval is now %d seconds", sec);
        return CLI_OK;
    }

    cli_print(cli, "Setting \"%s\" to \"%s\"", argv[0], argv[1]);
    return CLI_OK;
}

int cmd_config_int(
    struct cli_def *cli,
    UNUSED(char *command),
    char *argv[],
    int argc)
{
    if (argc < 1)
    {
        cli_print(cli, "Specify an interface to configure");
        return CLI_OK;
    }

    if (strcmp(argv[0], "?") == 0)
        cli_print(cli, "  test0/0");

    else if (strcasecmp(argv[0], "test0/0") == 0)
        cli_set_configmode(cli, MODE_CONFIG_INT, "test");
    else
        cli_print(cli, "Unknown interface %s", argv[0]);

    return CLI_OK;
}

int cmd_config_int_exit(
    struct cli_def *cli,
    UNUSED(char *command),
    UNUSED(char *argv[]),
    UNUSED(int argc))
{
    cli_set_configmode(cli, MODE_CONFIG, NULL);
    return CLI_OK;
}

int cmd_show_regular(
    struct cli_def *cli,
    UNUSED(char *command),
    char *argv[],
    int argc)
{
    cli_print(cli, "cli_regular() has run %u times", regular_count);
    return CLI_OK;
}

int cmd_debug_regular(
    struct cli_def *cli,
    UNUSED(char *command),
    char *argv[],
    int argc)
{
    debug_regular = !debug_regular;
    cli_print(cli, "cli_regular() debugging is %s",
              debug_regular ? "enabled" : "disabled");
    return CLI_OK;
}

int check_auth(
    char *username,
    char *password)
{
    //if (strcasecmp(username, "fred") != 0)
    if (strcasecmp(username, "f") != 0)
        return CLI_ERROR;
    //if (strcasecmp(password, "nerk") != 0)
    if (strcasecmp(password, "") != 0)
        return CLI_ERROR;
    return CLI_OK;
}

int regular_callback(
    struct cli_def *cli)
{
    regular_count++;
    if (debug_regular)
    {
        cli_print(cli, "Regular callback - %u times so far", regular_count);
        cli_reprompt(cli);
    }
    return CLI_OK;
}

int check_enable(
    char *password)
{
    return !strcasecmp(password, "topsecret");
}

int idle_timeout(
    struct cli_def *cli)
{
    cli_print(cli, "Custom idle timeout");
    return CLI_QUIT;
}

void pc(
    UNUSED(struct cli_def *cli),
    char *string)
{
    printf("%s\n", string);
}

int setup_cli(
    struct cli_def **cli_def)
{
    struct cli_command *c;

    signal(SIGCHLD, SIG_IGN);

    *cli_def = cli2_init();
    assert(*cli_def);
    struct cli_def *cli = *cli_def; // Legacy alias

    cli_set_banner(cli, "libcli test environment");
    cli_set_hostname(cli, "router");
    //cli_regular(cli, regular_callback);
    //cli_regular_interval(cli, 5); // Defaults to 1 second
    //cli_set_idle_timeout_callback(cli, 60, idle_timeout); // 60 second idle timeout
    cli_register_command(cli, NULL, "test", cmd_test, PRIVILEGE_UNPRIVILEGED,
        MODE_EXEC, NULL);

    cli_register_command(cli, NULL, "simple", NULL, PRIVILEGE_UNPRIVILEGED,
        MODE_EXEC, NULL);

    cli_register_command(cli, NULL, "simon", NULL, PRIVILEGE_UNPRIVILEGED,
        MODE_EXEC, NULL);

    cli_register_command(cli, NULL, "set", cmd_set, PRIVILEGE_PRIVILEGED,
        MODE_EXEC, NULL);

    c = cli_register_command(cli, NULL, "show", NULL, PRIVILEGE_UNPRIVILEGED,
        MODE_EXEC, NULL);

    cli_register_command(cli, c, "regular", cmd_show_regular, PRIVILEGE_UNPRIVILEGED,
        MODE_EXEC, "Show the how many times cli_regular has run");

    cli_register_command(cli, c, "counters", cmd_test, PRIVILEGE_UNPRIVILEGED,
        MODE_EXEC, "Show the counters that the system uses");

    cli_register_command(cli, c, "junk", cmd_test, PRIVILEGE_UNPRIVILEGED,
        MODE_EXEC, NULL);

    cli_register_command(cli, NULL, "interface", cmd_config_int,
        PRIVILEGE_PRIVILEGED, MODE_CONFIG, "Configure an interface");

    cli_register_command(cli, NULL, "exit", cmd_config_int_exit,
        PRIVILEGE_PRIVILEGED, MODE_CONFIG_INT,
        "Exit from interface configuration");

    cli_register_command(cli, NULL, "address", cmd_test, PRIVILEGE_PRIVILEGED,
        MODE_CONFIG_INT, "Set IP address");

    c = cli_register_command(cli, NULL, "debug", NULL, PRIVILEGE_UNPRIVILEGED,
        MODE_EXEC, NULL);

    cli_register_command(cli, c, "regular", cmd_debug_regular, PRIVILEGE_UNPRIVILEGED,
        MODE_EXEC, "Enable cli_regular() callback debugging");

    cli_set_auth_callback(cli, check_auth);
    cli_set_enable_callback(cli, check_enable);
    // Test reading from a file
    {
        FILE *fh;

        if ((fh = fopen("clitest.txt", "r")))
        {
            // This sets a callback which just displays the cli_print() text to stdout
            cli_print_callback(cli, pc);
            cli_file(cli, fh, PRIVILEGE_UNPRIVILEGED, MODE_EXEC);
            cli_print_callback(cli, NULL);
            fclose(fh);
        }
    }

    return 0;
}

int main(void)
{
    int max_queue = 128;

    struct sock_ev_serv server;
    bzero(&server, sizeof(struct sock_ev_serv));
    struct ev_periodic every_few_seconds;

    // Create our single-loop for this single-thread application
    EV_P  = ev_default_loop(0);

    ev_signal_init (&server.signal_watcher, sigint_cb, SIGINT);
    ev_signal_start (EV_A_ &server.signal_watcher);

    server.addr.sin_family = AF_INET;
    server.addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server.addr.sin_port = htons(CLITEST_PORT);

    server_init(&server, max_queue);

    // To be sure that we aren't actually blocking
    ev_periodic_init(&every_few_seconds, not_blocked, 0, 20., 0);
    ev_periodic_start(EV_A_ &every_few_seconds);

    // Get notified whenever the socket is ready to read
    ev_io_init(&server.io, server_cb, server.fd, EV_READ);
    ev_io_start(EV_A_ &server.io);

    // Run our loop, ostensibly forever
    puts("starting event loop ...\n");
    ev_loop(EV_A_ 0);

    // This point is only ever reached if the loop is manually exited
    puts("End of main(), cleaning up...\n");
    close(server.fd);
    list_cleanup_all(EV_A_ &server.io, &server);

    return EXIT_SUCCESS;
}

