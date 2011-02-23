#include <stdio.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "libcli.h"

// Includes from unix echo server code
#include <errno.h>
#include <fcntl.h>

#include <sys/un.h>

#include <ev.h>

#include "array-heap.h"
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
    int fd;
    struct sockaddr_un socket;
    int socket_len;
    array clients;
};

struct sock_ev_client {
    ev_io io;
    int fd;
    int index;
    struct sock_ev_serv* server;

    struct cli_def *cli;
};

int setnonblock(int fd);
static void not_blocked(EV_P_ ev_periodic *w, int revents);

unsigned int regular_count = 0;
unsigned int debug_regular = 0;
//------------
// This callback is called when client data is available
static void client_cb(EV_P_ ev_io *w, int revents) {
  // a client has become readable

  struct sock_ev_client* client = (struct sock_ev_client*) w;

  cli_process_event(EV_P_ ev_io *w, int revents, struct cli_def *cli)
  cli_process_event(w, revents, client->cli)

  /* int n; */
  /* char str[100] = ".\0"; */

  /* printf("[r]"); */
  /* n = recv(client->fd, str, 100, 0); */
  /* if (n <= 0) { */
  /*   if (0 == n) { */
  /*     // an orderly disconnect */
  /*     puts("orderly disconnect"); */
  /*     ev_io_stop(EV_A_ &client->io); */
  /*     close(client->fd); */
  /*   }  else if (EAGAIN == errno) { */
  /*     puts("should never get in this state with libev"); */
  /*   } else { */
  /*     perror("recv"); */
  /*   } */
  /*   return; */
  /* } */
  /* printf("socket client said: %s", str); */

  /* // Assuming that whenever a client is readable, it is also writable ? */
  /* if (send(client->fd, str, n, 0) < 0) { */
  /*   perror("send"); */
  /* } */
}

inline static struct sock_ev_client* client_new(int fd) {
  struct sock_ev_client* client;

  client = realloc(NULL, sizeof(struct sock_ev_client));
  client->fd = fd;
  //client->server = server;
  setnonblock(client->fd);
  ev_io_init(&client->io, client_cb, client->fd, EV_READ);

  return client;
}

// This callback is called when data is readable on the unix socket.
static void server_cb(EV_P_ ev_io *w, int revents) {
  puts("unix stream socket has become readable");

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
        g_warning("accept() failed errno=%i (%s)",  errno, strerror(errno));
        exit(EXIT_FAILURE);
      }
      break;
    }
    puts("accepted a client");
    client = client_new(client_fd);
    client->server = server;
    client->index = array_push(&server->clients, client);
    ev_io_start(EV_A_ &client->io);
  }
}

// Simply adds O_NONBLOCK to the file descriptor of choice
int setnonblock(int fd)
{
  int flags;

  flags = fcntl(fd, F_GETFL);
  flags |= O_NONBLOCK;
  return fcntl(fd, F_SETFL, flags);
}

int socket_init(struct sockaddr_un* socket_un, int max_queue) {
  int fd;

  // Setup a socket listener.

  if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
  {
      perror("socket");
      exit(EXIT_FAILURE);
  }
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));


  // Set it non-blocking
  if (-1 == setnonblock(fd)) {
    perror("echo server socket nonblock");
    exit(EXIT_FAILURE);
  }

  // Set it as unix socket
  socket_un->sun_family = AF_INET;
  //strcpy(socket_un->sun_path, sock_path);

  return fd;
}

int server_init(struct sock_ev_serv* server, int max_queue) {
    server->fd = socket_init(&server->socket, max_queue);
    //server->socket_len = sizeof(server->socket.sun_family) + strlen(server->socket.sun_path);
    server->socket_len = sizeof(server->socket.sun_family));

    array_init(&server->clients, 128);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(CLITEST_PORT);

    if (-1 == bind(server->fd, (struct sockaddr*) &server->socket, server->socket_len))
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

int main(void) {
    int max_queue = 128;
    struct sock_ev_serv server;
    struct ev_periodic every_few_seconds;

    int result = setup_cli();
    if (result < 0) {
        perror("CLI setup failed");
        exit(EXIT_FAILURE);
    }

    // Create our single-loop for this single-thread application
    EV_P  = ev_default_loop(0);

    // Create unix socket in non-blocking fashion
    //server_init(&server, "/tmp/libev-echo.sock", max_queue);
    server_init(&server, max_queue);

    // To be sure that we aren't actually blocking
    ev_periodic_init(&every_few_seconds, not_blocked, 0, 5, 0);
    ev_periodic_start(EV_A_ &every_few_seconds);

    // Get notified whenever the socket is ready to read
    ev_io_init(&server.io, server_cb, server.fd, EV_READ);
    ev_io_start(EV_A_ &server.io);

    // Run our loop, ostensibly forever
    puts("tcp-socket-echo starting...\n");
    ev_loop(EV_A_ 0);

    // This point is only ever reached if the loop is manually exited
    close(server.fd);
    return EXIT_SUCCESS;
}


static void not_blocked(EV_P_ ev_periodic *w, int revents) {
  puts("I'm not blocked");
}


//------------
int cmd_test(struct cli_def *cli, char *command, char *argv[], int argc)
{
    int i;
    cli_print(cli, "called %s with \"%s\"", __FUNCTION__, command);
    cli_print(cli, "%d arguments:", argc);
    for (i = 0; i < argc; i++)
        cli_print(cli, "        %s", argv[i]);

    return CLI_OK;
}

int cmd_set(struct cli_def *cli, UNUSED(char *command), char *argv[],
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

int cmd_config_int(struct cli_def *cli, UNUSED(char *command), char *argv[],
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

int cmd_config_int_exit(struct cli_def *cli, UNUSED(char *command),
    UNUSED(char *argv[]), UNUSED(int argc))
{
    cli_set_configmode(cli, MODE_CONFIG, NULL);
    return CLI_OK;
}

int cmd_show_regular(struct cli_def *cli, UNUSED(char *command), char *argv[], int argc)
{
    cli_print(cli, "cli_regular() has run %u times", regular_count);
    return CLI_OK;
}

int cmd_debug_regular(struct cli_def *cli, UNUSED(char *command), char *argv[], int argc)
{
    debug_regular = !debug_regular;
    cli_print(cli, "cli_regular() debugging is %s", debug_regular ? "enabled" : "disabled");
    return CLI_OK;
}

int check_auth(char *username, char *password)
{
    if (strcasecmp(username, "fred") != 0)
        return CLI_ERROR;
    if (strcasecmp(password, "nerk") != 0)
        return CLI_ERROR;
    return CLI_OK;
}

int regular_callback(struct cli_def *cli)
{
    regular_count++;
    if (debug_regular)
    {
        cli_print(cli, "Regular callback - %u times so far", regular_count);
        cli_reprompt(cli);
    }
    return CLI_OK;
}

int check_enable(char *password)
{
    return !strcasecmp(password, "topsecret");
}

int idle_timeout(struct cli_def *cli)
{
    cli_print(cli, "Custom idle timeout");
    return CLI_QUIT;
}

void pc(UNUSED(struct cli_def *cli), char *string)
{
    printf("%s\n", string);
}

int setup_cli()
{
    struct cli_command *c;
    struct cli_def *cli;
    int s, x;
    struct sockaddr_in addr;
    int on = 1;


    signal(SIGCHLD, SIG_IGN);

    cli = cli_init();
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

//-- old main
int old_main()
{


    while ((x = accept(s, NULL, 0)))
    {
        int pid = fork();
        if (pid < 0)
        {
            perror("fork");
            return 1;
        }

        /* parent */
        if (pid > 0)
        {
            socklen_t len = sizeof(addr);
            if (getpeername(x, (struct sockaddr *) &addr, &len) >= 0)
                printf(" * accepted connection from %s\n", inet_ntoa(addr.sin_addr));

            close(x);
            continue;
        }

        /* child */
        close(s);
        cli_loop(cli, x);
        exit(0);
    }

    cli_done(cli);
    return 0;
}
