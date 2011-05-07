#include <stdlib.h>
#include <string.h>

#include "libcli.h"

#include "libcli_wrapper.h"

#include "iputils.h"
#include "elog.h"

#define CLITEST_PORT                8000

struct CliData {
    int dummy[10000];
};

static struct CliData *cli_data = NULL;
static struct Cli *cli = NULL;

void do_cleanup()
{
    INFO("Exiting program, entering do_cleanup()");
    EV_P  = ev_default_loop(0);

    free(cli_data); // We do not free this in cliwrap_cleanup() since it is
                    // void udata
    cliwrap_cleanup(EV_A_ &cli);
}

static void
sigint_cb (
    EV_P_ ev_signal *w,
    int revents)
{
    printf("\nGot signal %d\n", w->signum);

    ev_unloop (EV_A_ EVUNLOOP_ALL);
}

int main(void)
{

    char cli_str[128];
    char port_str[128];

    cli_data = calloc(1, sizeof(struct CliData));

    EV_P  = ev_default_loop(0);

    ev_signal signal_watcher;
    ev_signal_init (&signal_watcher, sigint_cb, SIGINT);
    ev_signal_start (EV_A_ &signal_watcher);

    strcpy(cli_str, "localhost");
    INFO("Using addr '%s' for cli server", cli_str);
    sprintf(port_str, "%u", CLITEST_PORT);

    if ( (cli = cliwrap_init(EV_A_ cli_str, port_str,
                             1, cli_data)) == 0 )
    {
        ERR("Unable to setup cli...");
    }

    // Run our loop, ostensibly forever
    puts("starting event loop ...\n");
    ev_loop(EV_A_ 0);

    do_cleanup();

    ev_default_destroy();
    return 0; /* atexit() fcn called for cleanup */
}

